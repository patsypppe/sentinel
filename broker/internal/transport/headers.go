package transport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// The header contract, docs/HANDOFF.md §8.2.
//
// Streamable HTTP POST requires Mcp-Method on every request, and Mcp-Name on the
// three methods the specification's Standard Request Headers table names:
// tools/call, resources/read and prompts/get. The reason is architectural rather
// than cosmetic: a gateway or WAF must be able to route and authorize WITHOUT
// PARSING THE JSON BODY. envoy/envoy.yaml does exactly that, and
// tests/e2e/test_header_routing.py asserts its filter chain contains nothing
// that could read a body.
//
// The server's job is the other half of the pair: it validates the headers
// against the body, so a gateway that routed on the headers and a server that
// acted on the body can never disagree about what happened. Routed by header,
// rejected by body check — that pair is the demonstration.
//
// Both directions of that validation matter. Each header is SOURCED FROM A BODY
// FIELD — Mcp-Method from `method`, Mcp-Name from `params.name` or `params.uri`
// — and the specification requires rejecting "requests where the values
// specified in the headers do not match the corresponding values in the request
// body". A method with neither params field has no corresponding value, so an
// Mcp-Name on a tools/list asserts a body value that does not exist and cannot
// be matched: it is refused rather than ignored. Requiring one there would be
// the mirror-image defect — demanding a header the specification does not
// define for the method, and refusing conformant traffic because of it.

const (
	HeaderMcpMethod = "Mcp-Method"
	HeaderMcpName   = "Mcp-Name"
)

// HeaderMismatchData tells the client precisely which of the two headers
// disagreed and what the body said, so the fix is obvious from the error alone.
type HeaderMismatchData struct {
	Header      string `json:"header"`
	HeaderValue string `json:"headerValue"`
	BodyValue   string `json:"bodyValue"`
}

// ValidateHeaders enforces the contract against the parsed request.
func ValidateHeaders(h http.Header, req envelope.Request) *envelope.RPCError {
	method := h.Get(HeaderMcpMethod)
	if method == "" {
		return envelope.New(envelope.CodeHeaderMismatch,
			fmt.Sprintf("%s is required on Streamable HTTP POST so a gateway can route "+
				"without parsing the body; expected %q", HeaderMcpMethod, req.Method),
			HeaderMismatchData{Header: HeaderMcpMethod, HeaderValue: "", BodyValue: req.Method})
	}
	if method != req.Method {
		return envelope.New(envelope.CodeHeaderMismatch,
			fmt.Sprintf("%s is %q but the JSON-RPC body says %q", HeaderMcpMethod, method, req.Method),
			HeaderMismatchData{Header: HeaderMcpMethod, HeaderValue: method, BodyValue: req.Method})
	}

	wantName, takesName, err := ExpectedMcpName(req)
	if err != nil {
		return err
	}

	name := h.Get(HeaderMcpName)
	if !takesName {
		if name != "" {
			return envelope.New(envelope.CodeHeaderMismatch,
				fmt.Sprintf("%s is defined for %s only; %s carries no params.name or "+
					"params.uri, so the header asserts a body value that does not exist",
					HeaderMcpName, nameBearingList(), req.Method),
				HeaderMismatchData{Header: HeaderMcpName, HeaderValue: name, BodyValue: ""})
		}
		return nil
	}
	if name == "" {
		return envelope.New(envelope.CodeHeaderMismatch,
			fmt.Sprintf("%s is required on a %s POST; expected %q", HeaderMcpName, req.Method, wantName),
			HeaderMismatchData{Header: HeaderMcpName, HeaderValue: "", BodyValue: wantName})
	}
	if name != wantName {
		return envelope.New(envelope.CodeHeaderMismatch,
			fmt.Sprintf("%s is %q but the JSON-RPC body names %q", HeaderMcpName, name, wantName),
			HeaderMismatchData{Header: HeaderMcpName, HeaderValue: name, BodyValue: wantName})
	}

	return nil
}

// namedParams is the shape of every method that takes a name. Decoded into
// named string fields rather than map[string]any so a numeric-looking name
// cannot round-trip through float64 (§14 gotcha 2).
type namedParams struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

// ExpectedMcpName reports what Mcp-Name must be for a request, and whether the
// header is defined for the method at all.
//
// takesName is false for every method outside the specification's Mcp-Name row
// — tools/call, resources/read, prompts/get. Those methods have no params.name
// or params.uri, so there is nothing for a header to be matched against and
// Mcp-Name must be ABSENT rather than set to anything, the method name included.
// Callers that build a request use takesName to decide whether to send the
// header at all.
func ExpectedMcpName(req envelope.Request) (string, bool, *envelope.RPCError) {
	field, takesName := nameBearingMethods[req.Method]
	if !takesName {
		return "", false, nil
	}

	var p namedParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return "", true, envelope.ErrInvalidParams("params", err.Error(), "must be an object")
		}
	}

	value := p.Name
	if field == nameFieldURI {
		value = p.URI
	}
	if value == "" {
		return "", true, envelope.ErrInvalidParams(string(field), "",
			fmt.Sprintf("is required for %s and must match the %s header", req.Method, HeaderMcpName))
	}
	return value, true, nil
}

// nameBearingList renders the three methods in a stable order, so the refusal
// tells the client which methods the header IS defined for rather than only
// which one it is not.
func nameBearingList() string {
	methods := make([]string, 0, len(nameBearingMethods))
	for m := range nameBearingMethods {
		methods = append(methods, m)
	}
	sort.Strings(methods)
	return strings.Join(methods, ", ")
}

type nameField string

const (
	nameFieldName nameField = "name"
	nameFieldURI  nameField = "uri"
)

// nameBearingMethods maps each method that takes a name to the params field
// carrying it. It is the specification's Mcp-Name row, exactly: every method
// absent from this map sends no Mcp-Name at all.
var nameBearingMethods = map[string]nameField{
	envelope.MethodToolsCall:     nameFieldName,
	envelope.MethodResourcesRead: nameFieldURI,
	"prompts/get":                nameFieldName,
}
