package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/patsypppe/sentinel/broker/internal/canonical"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// Deterministic manifest construction, docs/HANDOFF.md §8.3:
//
//  1. Sort tools by name, byte-wise over the UTF-8 encoding. Not locale
//     collation, not case-insensitive — bytes.Compare semantics.
//  2. Within each tool, emit fields in a fixed struct order.
//  3. Sort every `required` array and every `enum` array.
//  4. Serialize with no insignificant whitespace.
//  5. manifest_hash = "sha256:" + hex(sha256(bytes))
//
// This is measurable, so it is measured: TestToolsListByteStable calls the
// manifest 100 times and asserts exactly one distinct SHA-256, then reloads the
// registry and asserts the hash is unchanged. Reload is where determinism
// usually dies, because a map got iterated somewhere.

// schemaSortKeys names the schema array fields whose order carries no meaning
// but does change the hash.
var schemaSortKeys = map[string]bool{
	"required": true,
	"enum":     true,
}

// build sorts, canonicalizes, hashes and measures. Called once, at construction.
func (r *Registry) build() error {
	r.ordered = make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		r.ordered = append(r.ordered, t)
	}

	// Step 1. sort.Slice with bytes.Compare on the UTF-8 bytes. Using
	// strings.ToLower here — or any locale-aware collation — would put
	// "Warehouse" and "warehouse" in an order that depends on where the server
	// runs, which is exactly the class of bug this whole file exists to prevent.
	sort.Slice(r.ordered, func(i, j int) bool {
		return bytes.Compare([]byte(r.ordered[i].Name()), []byte(r.ordered[j].Name())) < 0
	})

	// Step 2. ToolDescriptor's field order is the emission order; the struct
	// declaration is the single source of truth for it.
	descriptors := make([]envelope.ToolDescriptor, 0, len(r.ordered))
	for _, t := range r.ordered {
		d := descriptorFor(t)

		// Step 3.
		in, err := canonicalizeSchema(d.InputSchema)
		if err != nil {
			return fmt.Errorf("registry: %q input schema: %w", t.Name(), err)
		}
		d.InputSchema = in

		out, err := canonicalizeSchema(d.OutputSchema)
		if err != nil {
			return fmt.Errorf("registry: %q output schema: %w", t.Name(), err)
		}
		d.OutputSchema = out

		// Scopes are a set; their order carries no meaning either.
		sort.Strings(d.Scopes)

		descriptors = append(descriptors, d)
	}

	// Step 4. Marshal through the struct. encoding/json emits struct fields in
	// declaration order with no insignificant whitespace, which is steps 2 and 4
	// in one operation.
	//
	// Note what is deliberately NOT done here: the descriptor's own keys are not
	// alphabetized. Step 2 asks for "a fixed struct order", and ToolDescriptor's
	// declaration is that order. Running canonical.With over the finished array
	// would reorder those keys into `cacheScope, cacheTtlMs, description, …`,
	// which is stable but is not the specified order — and it would make the
	// bytes a client receives differ from the bytes that were hashed, since the
	// client decodes into the same struct. Canonicalization applies to the
	// nested schemas, where the key order is genuinely arbitrary.
	manifest, err := json.Marshal(descriptors)
	if err != nil {
		return fmt.Errorf("registry: marshal manifest: %w", err)
	}
	r.manifest = manifest

	// Step 5.
	sum := sha256.Sum256(manifest)
	r.hash = "sha256:" + hex.EncodeToString(sum[:])

	r.tokens = countTokens(r.ordered, manifest)
	return nil
}

func descriptorFor(t Tool) envelope.ToolDescriptor {
	cp := t.CachePolicy()
	scopes := append([]string(nil), t.Scopes()...)
	if scopes == nil {
		scopes = []string{}
	}
	return envelope.ToolDescriptor{
		Name:          t.Name(),
		Description:   t.Description(),
		InputSchema:   t.InputSchema(),
		OutputSchema:  t.OutputSchema(),
		Scopes:        scopes,
		Reversibility: string(t.Reversibility()),
		TokenCap:      t.TokenCap(),
		CacheTTLMs:    cp.TTLMs,
		CacheScope:    cp.Scope,
	}
}

// canonicalizeSchema orders a JSON Schema's keys and sorts its `required` and
// `enum` arrays, whose order carries no meaning.
func canonicalizeSchema(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	out, err := canonical.With(raw, canonical.Options{SortArrayKeys: schemaSortKeys})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ToolsListResult builds the tools/list payload from the precomputed manifest.
//
// The descriptors are re-decoded from the canonical bytes rather than rebuilt
// from the tools, so what a client receives is byte-identical to what was
// hashed. Building them a second way would be a second chance to diverge.
func (r *Registry) ToolsListResult(policy envelope.CachePolicy) (*envelope.ToolsListResult, error) {
	var descriptors []envelope.ToolDescriptor
	if err := json.Unmarshal(r.manifest, &descriptors); err != nil {
		return nil, fmt.Errorf("registry: decode manifest: %w", err)
	}
	res := &envelope.ToolsListResult{
		Tools:        descriptors,
		ManifestHash: r.hash,
	}
	res.SetCache(policy)
	return res, nil
}
