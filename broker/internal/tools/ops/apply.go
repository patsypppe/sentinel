package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/mrtr"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Resolver resolves a principal-bound handle. Declared where it is used.
type Resolver interface {
	ResolveTyped(ctx context.Context, p registry.Principal, id, wantKind string, into any) error
}

// ApplyTool is ops.deployment_apply — the reason MRTR exists in this project.
//
// It is Irreversible, and that single declaration is what forces confirmation.
// registry.Reversibility.RequiresConfirmation returns true for Irreversible
// unconditionally, with no threshold and no exception, so a future maintainer
// cannot make this tool skip its round trip by forgetting a check. The type
// system asks the question; the code cannot decline to answer it.
type ApplyTool struct {
	engine  *mrtr.Engine
	handles Resolver
}

func NewApplyTool(engine *mrtr.Engine, handles Resolver) *ApplyTool {
	return &ApplyTool{engine: engine, handles: handles}
}

func (t *ApplyTool) Name() string { return "ops.deployment_apply" }

func (t *ApplyTool) Description() string {
	return "Apply a deployment plan produced by ops.deployment_plan. This is irreversible " +
		"and always requires confirmation: the first call returns resultType " +
		"\"input_required\"; retry the identical request with inputResponses and the " +
		"requestState you were given. Retrying a completed request returns the recorded " +
		"result and does not deploy again."
}

func (t *ApplyTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "plan": {
          "type": "string",
          "description": "The handle returned by ops.deployment_plan."
        },
        "inputResponses": {
          "type": "object",
          "description": "Present only on a retry. Carries the confirmation you were asked for.",
          "properties": {"confirm": {"type": "boolean"}}
        },
        "requestState": {
          "type": "string",
          "description": "Present only on a retry. Opaque; return exactly what you were given."
        }
      },
      "required": ["plan"],
      "additionalProperties": false
    }`)
}

func (t *ApplyTool) OutputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "deployed":      {"type": "boolean"},
        "deploymentId":  {"type": "string"},
        "service":       {"type": "string"},
        "version":       {"type": "string"}
      },
      "required": ["deployed"]
    }`)
}

func (t *ApplyTool) Scopes() []string { return []string{"ops:apply"} }

// Reversibility is Irreversible. Everything above follows from this line.
func (t *ApplyTool) Reversibility() registry.Reversibility { return registry.Irreversible }

// CachePolicy: a result that must never be served from a cache to anyone. The
// TTL is zero and the scope is private — an irreversible action's outcome is
// replayed through MRTR, which is a different mechanism with different rules.
func (t *ApplyTool) CachePolicy() envelope.CachePolicy {
	return envelope.CachePolicy{TTLMs: 0, Scope: envelope.ScopePrivate}
}

func (t *ApplyTool) TokenCap() int { return 2_000 }

type applyArgs struct {
	Plan           string          `json:"plan"`
	InputResponses json.RawMessage `json:"inputResponses,omitempty"`
	RequestState   string          `json:"requestState,omitempty"`
}

// confirmationRequests is what the client is asked for. Destructive is set so a
// client that renders confirmations differently for destructive actions can.
func confirmationRequests(plan Plan) []envelope.InputRequest {
	return []envelope.InputRequest{{
		Name: "confirm",
		Kind: "boolean",
		Prompt: fmt.Sprintf(
			"Deploy %s %s across %d replicas? This is irreversible.",
			plan.Service, plan.Version, plan.Replicas),
		Schema:      json.RawMessage(`{"type":"boolean"}`),
		Destructive: true,
	}}
}

func (t *ApplyTool) Call(ctx context.Context, p registry.Principal, raw json.RawMessage) (registry.Result, error) {
	var args applyArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("%q could not be parsed as an object: %w", "arguments", err)
		}
	}
	if args.Plan == "" {
		return nil, errors.New(`"plan" is required: pass the handle returned by ops.deployment_plan`)
	}

	// The plan handle is resolved on BOTH the first call and the retry.
	// Possession of the handle is not authentication, so it is re-verified
	// against this principal every time rather than trusted because it was
	// checked once at the start of the flow.
	var plan Plan
	if err := t.handles.ResolveTyped(ctx, p, args.Plan, HandleKindDeploymentPlan, &plan); err != nil {
		return nil, err
	}

	// The retry path.
	if args.RequestState != "" {
		return t.resume(ctx, p, args, plan)
	}

	// The first call. Nothing happens here beyond opening the flow: the effect
	// runs only inside Resume, and only once.
	//
	// The hash covers the arguments MINUS the retry-only fields, so that the
	// retry — which necessarily adds them — is not read as a mutation.
	state, err := t.engine.Begin(ctx, p, t.Name(), approvedArguments(args), confirmationRequests(plan))
	if err != nil {
		return nil, err
	}

	return &envelope.ToolsCallResult{
		InputRequests: confirmationRequests(plan),
		RequestState:  state,
		Content: []envelope.ContentBlock{{
			Type: "text",
			Text: fmt.Sprintf("Confirmation required before deploying %s %s. "+
				"Retry this request with inputResponses and the requestState provided.",
				plan.Service, plan.Version),
		}},
	}, nil
}

// approvedArguments is the subset of the call that the user's approval covers.
//
// requestState and inputResponses are present only on the retry, so hashing the
// whole argument object would make every retry look like a mutation. Everything
// that determines WHAT HAPPENS — here, the plan handle — is inside the hash.
func approvedArguments(args applyArgs) json.RawMessage {
	// Built from a struct rather than by deleting keys from the raw message, so
	// a field added to applyArgs later is not silently included in the approved
	// set without someone deciding it should be.
	encoded, err := json.Marshal(struct {
		Plan string `json:"plan"`
	}{Plan: args.Plan})
	if err != nil {
		// Marshalling a struct of one string cannot fail; if it somehow does,
		// an empty object hashes consistently and the flow simply will not match.
		return json.RawMessage(`{}`)
	}
	return encoded
}

func (t *ApplyTool) resume(ctx context.Context, p registry.Principal, args applyArgs, plan Plan) (registry.Result, error) {
	confirmed, err := confirmationGiven(args.InputResponses)
	if err != nil {
		return nil, err
	}
	if !confirmed {
		// A declined confirmation is a completed interaction, not an error. The
		// flow is left awaiting input so the client may confirm later; nothing
		// has happened either way.
		payload, _ := json.Marshal(struct {
			Deployed bool `json:"deployed"`
		}{Deployed: false})
		return &envelope.ToolsCallResult{
			StructuredContent: payload,
			Content: []envelope.ContentBlock{{
				Type: "text",
				Text: "Confirmation was declined. Nothing was deployed.",
			}},
		}, nil
	}

	outcome, err := t.engine.Resume(ctx, p, args.RequestState, t.Name(),
		approvedArguments(args), t.deploy(p, plan))
	if err != nil {
		return nil, err
	}

	text := fmt.Sprintf("Deployed %s %s.", plan.Service, plan.Version)
	if outcome.Replayed {
		text = fmt.Sprintf("This request already completed. %s %s was deployed once; "+
			"this reply is the recorded result and nothing was deployed again.",
			plan.Service, plan.Version)
	}

	return &envelope.ToolsCallResult{
		StructuredContent: outcome.Result,
		Content:           []envelope.ContentBlock{{Type: "text", Text: text}},
	}, nil
}

// deploy is the effect. It runs inside the engine's transaction, so the
// deployment row and the flow's recorded result commit together or not at all.
func (t *ApplyTool) deploy(p registry.Principal, plan Plan) mrtr.Effect {
	return func(ctx context.Context, tx pgx.Tx, correlationID string, _ json.RawMessage) (json.RawMessage, error) {
		// The attempt row is recorded first and unconditionally. It is what the
		// idempotency test counts, and counting it rather than the deployments
		// table is what makes that test measure the ENGINE rather than the
		// UNIQUE constraint behind it.
		if _, err := tx.Exec(ctx,
			`INSERT INTO deployment_attempts (correlation_id) VALUES ($1)`, correlationID); err != nil {
			return nil, fmt.Errorf("ops: record attempt: %w", err)
		}

		encodedPlan, err := json.Marshal(plan)
		if err != nil {
			return nil, fmt.Errorf("ops: encode plan: %w", err)
		}

		deploymentID := uuid.New()
		if _, err := tx.Exec(ctx,
			`INSERT INTO deployments (deployment_id, tenant_id, principal_id, plan, correlation_id)
			 VALUES ($1, $2, $3, $4, $5)`,
			deploymentID, p.TenantID, p.ID, encodedPlan, correlationID); err != nil {
			return nil, fmt.Errorf("ops: apply deployment: %w", err)
		}

		return json.Marshal(struct {
			Deployed     bool   `json:"deployed"`
			DeploymentID string `json:"deploymentId"`
			Service      string `json:"service"`
			Version      string `json:"version"`
		}{
			Deployed:     true,
			DeploymentID: deploymentID.String(),
			Service:      plan.Service,
			Version:      plan.Version,
		})
	}
}

func confirmationGiven(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 {
		return false, errors.New(`"inputResponses" is required on a retry; ` +
			`try {"inputResponses":{"confirm":true}}`)
	}
	var responses struct {
		Confirm *bool `json:"confirm"`
	}
	if err := json.Unmarshal(raw, &responses); err != nil {
		return false, fmt.Errorf(`"inputResponses" could not be parsed: %w; `+
			`try {"confirm":true}`, err)
	}
	if responses.Confirm == nil {
		return false, errors.New(`"inputResponses.confirm" is required and must be a boolean; ` +
			`try {"confirm":true}`)
	}
	return *responses.Confirm, nil
}
