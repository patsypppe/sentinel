// Package ops implements the deployment tool pair.
//
// It exists to make the MRTR demo real (docs/HANDOFF.md §9.3). What matters is
// not that it deploys anything, but that ops.deployment_apply is IRREVERSIBLE
// BY DECLARATION — so the type system requires its confirmation rather than a
// developer remembering to — and that its effect increments a counter a test
// can assert on.
package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Minter mints principal-bound state handles. Declared here, where it is used.
type Minter interface {
	Mint(ctx context.Context, p registry.Principal, kind string, payload json.RawMessage, ttl time.Duration) (string, error)
}

// HandleKindDeploymentPlan labels a plan handle.
const HandleKindDeploymentPlan = "deployment_plan"

// defaultReplicas is used only when the caller omits the field entirely.
const defaultReplicas = 3

// Plan is what deployment_plan produces and deployment_apply consumes.
type Plan struct {
	Service  string   `json:"service"`
	Version  string   `json:"version"`
	Replicas int      `json:"replicas"`
	Steps    []string `json:"steps"`
}

// PlanTool is ops.deployment_plan.
type PlanTool struct {
	minter    Minter
	handleTTL time.Duration
}

func NewPlanTool(minter Minter, handleTTL time.Duration) *PlanTool {
	if handleTTL <= 0 {
		handleTTL = 15 * time.Minute
	}
	return &PlanTool{minter: minter, handleTTL: handleTTL}
}

func (t *PlanTool) Name() string { return "ops.deployment_plan" }

func (t *PlanTool) Description() string {
	return "Compute a deployment plan and return a handle to it. Planning changes nothing. " +
		"Pass the returned handle to ops.deployment_apply, which will ask for confirmation " +
		"before it does anything irreversible."
}

func (t *PlanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "service":  {"type": "string", "description": "The service to deploy, e.g. \"checkout\"."},
        "version":  {"type": "string", "description": "The version to deploy, e.g. \"1.4.2\"."},
        "replicas": {"type": "integer", "minimum": 1, "maximum": 50, "default": 3}
      },
      "required": ["service", "version"],
      "additionalProperties": false
    }`)
}

func (t *PlanTool) OutputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "handle": {"type": "string", "description": "Pass this to ops.deployment_apply."},
        "plan": {
          "type": "object",
          "properties": {
            "service":  {"type": "string"},
            "version":  {"type": "string"},
            "replicas": {"type": "integer"},
            "steps":    {"type": "array", "items": {"type": "string"}}
          },
          "required": ["service", "version", "steps"]
        }
      },
      "required": ["handle", "plan"]
    }`)
}

func (t *PlanTool) Scopes() []string { return []string{"ops:plan"} }

// Reversibility is Reversible: planning computes and stores, and changes
// nothing that anyone can observe outside this server.
func (t *PlanTool) Reversibility() registry.Reversibility { return registry.Reversible }

// CachePolicy: not cacheable in any useful sense — every call mints a fresh
// handle — so the TTL is short and the scope is private.
func (t *PlanTool) CachePolicy() envelope.CachePolicy {
	return envelope.CachePolicy{TTLMs: 5_000, Scope: envelope.ScopePrivate}
}

func (t *PlanTool) TokenCap() int { return 4_000 }

type planArgs struct {
	Service string `json:"service"`
	Version string `json:"version"`
	// Replicas is a pointer so that ABSENT and an explicit 0 are
	// distinguishable. With a plain int they share the zero value, so
	// {"replicas": 0} would silently become the default of 3 — the schema says
	// minimum 1, and quietly substituting a different number for one the caller
	// explicitly asked for is worse than refusing it.
	Replicas *int `json:"replicas"`
}

func (t *PlanTool) Call(ctx context.Context, p registry.Principal, raw json.RawMessage) (registry.Result, error) {
	var args planArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("%q could not be parsed as an object: %w", "arguments", err)
		}
	}
	if args.Service == "" {
		return nil, fmt.Errorf(`"service" is required; try {"service":"checkout","version":"1.4.2"}`)
	}
	if args.Version == "" {
		return nil, fmt.Errorf(`"version" is required; try {"service":%q,"version":"1.4.2"}`, args.Service)
	}
	replicas := defaultReplicas
	if args.Replicas != nil {
		replicas = *args.Replicas
		if replicas < 1 || replicas > 50 {
			return nil, fmt.Errorf(`"replicas" must be between 1 and 50; got %d; try %d`,
				replicas, defaultReplicas)
		}
	}

	plan := Plan{
		Service:  args.Service,
		Version:  args.Version,
		Replicas: replicas,
		Steps: []string{
			fmt.Sprintf("drain %s", args.Service),
			fmt.Sprintf("roll %s to %s across %d replicas", args.Service, args.Version, replicas),
			fmt.Sprintf("verify %s health", args.Service),
		},
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("ops: encode plan: %w", err)
	}

	handle, err := t.minter.Mint(ctx, p, HandleKindDeploymentPlan, encoded, t.handleTTL)
	if err != nil {
		return nil, fmt.Errorf("ops: mint plan handle: %w", err)
	}

	payload, err := json.Marshal(struct {
		Handle string `json:"handle"`
		Plan   Plan   `json:"plan"`
	}{Handle: handle, Plan: plan})
	if err != nil {
		return nil, fmt.Errorf("ops: encode result: %w", err)
	}

	return &envelope.ToolsCallResult{
		StructuredContent: payload,
		Content: []envelope.ContentBlock{{
			Type: "text",
			Text: fmt.Sprintf("Planned %s %s across %d replicas in %d steps. "+
				"Nothing has changed yet — pass handle %s to ops.deployment_apply to proceed.",
				plan.Service, plan.Version, plan.Replicas, len(plan.Steps), handle),
		}},
	}, nil
}
