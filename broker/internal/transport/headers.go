package transport

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// The header contract, docs/HANDOFF.md §8.2.
//
// Streamable HTTP POST requires Mcp-Method and Mcp-Name. The reason is
// architectural rather than cosmetic: a gateway or WAF must be able to route and
// authorize WITHOUT PARSING THE JSON BODY. envoy/envoy.yaml does exactly that,
// and tests/e2e/test_header_routing.py asserts its filter chain contains nothing
// that could read a body.
//
// The server's job is the other half of the pair: it validates the headers
// against the body, so a gateway that routed on the headers and a server that
// acted on the body can never disagree about what happened. Routed by header,
// rejected by body check — that pair is the demonstration.

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

	wantName, err := ExpectedMcpName(req)
	if err != nil {
		return err
	}

	name := h.Get(HeaderMcpName)
	if name == "" {
		return envelope.New(envelope.CodeHeaderMismatch,
			fmt.Sprintf("%s is required on Streamable HTTP POST; expected %q", HeaderMcpName, wantName),
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

// ExpectedMcpName computes what Mcp-Name must be for a request: the tool,
// prompt or resource name where the method takes one, and the method name
// otherwise.
func ExpectedMcpName(req envelope.Request) (string, *envelope.RPCError) {
	field, takesName := nameBearingMethods[req.Method]
	if !takesName {
		return req.Method, nil
	}

	var p namedParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return "", envelope.ErrInvalidParams("params", err.Error(), "must be an object")
		}
	}

	value := p.Name
	if field == nameFieldURI {
		value = p.URI
	}
	if value == "" {
		return "", envelope.ErrInvalidParams(string(field), "",
			fmt.Sprintf("is required for %s and must match the %s header", req.Method, HeaderMcpName))
	}
	return value, nil
}

type nameField string

const (
	nameFieldName nameField = "name"
	nameFieldURI  nameField = "uri"
)

// nameBearingMethods maps each method that takes a name to the params field
// carrying it. Everything absent from this map uses its own method name.
var nameBearingMethods = map[string]nameField{
	envelope.MethodToolsCall:     nameFieldName,
	envelope.MethodResourcesRead: nameFieldURI,
	"prompts/get":                nameFieldName,
}
