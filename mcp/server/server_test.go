package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patsypppe/sentinel/mcp/envelope"
	"github.com/patsypppe/sentinel/mcp/example"
	"github.com/patsypppe/sentinel/mcp/registry"
	"github.com/patsypppe/sentinel/mcp/server"
)

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientCapabilities":{}}`

func post(t *testing.T, srv *httptest.Server, method, name, params string) (int, map[string]any) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":"1","method":"` + method + `","params":{` + params + meta + `}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Method", method)
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not JSON (HTTP %d): %s", resp.StatusCode, raw)
	}
	return resp.StatusCode, out
}

func started(t *testing.T) (*server.Server, *httptest.Server) {
	t.Helper()
	s, err := example.New()
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(s.Handler())
	t.Cleanup(h.Close)
	return s, h
}

func TestNewRefusesAServerThatHasNotSaidHowItIdentifiesCallers(t *testing.T) {
	_, err := server.New(server.Options{
		Info:  envelope.Info{Name: "x"},
		Tools: []registry.Tool{example.Reverse{}},
	})
	if err == nil || !strings.Contains(err.Error(), "Authenticator is required") {
		t.Fatalf("err = %v, want a refusal naming the authenticator", err)
	}
}

func TestNewRefusesAServerWithNoName(t *testing.T) {
	_, err := server.New(server.Options{Authenticator: server.InsecureAnonymous(registry.Principal{})})
	if err == nil || !strings.Contains(err.Error(), "Info.Name") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewRefusesATwiceRegisteredTool(t *testing.T) {
	_, err := server.New(server.Options{
		Info:          envelope.Info{Name: "x"},
		Authenticator: server.InsecureAnonymous(registry.Principal{}),
		Tools:         []registry.Tool{example.Reverse{}, example.Reverse{}},
	})
	if err == nil || !strings.Contains(err.Error(), "registered twice") {
		t.Fatalf("err = %v", err)
	}
}

func TestEveryResultCarriesResultTypeAndServerInfo(t *testing.T) {
	_, h := started(t)
	for _, c := range []struct{ method, name, params string }{
		{"server/discover", "", ""},
		{"tools/list", "", ""},
		{"tools/call", "echo.reverse", `"name":"echo.reverse","arguments":{"text":"abc"},`},
	} {
		_, out := post(t, h, c.method, c.name, c.params)
		result, ok := out["result"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no result: %v", c.method, out)
		}
		if result["resultType"] != "complete" {
			t.Errorf("%s: resultType = %v", c.method, result["resultType"])
		}
		m, _ := result["_meta"].(map[string]any)
		if m["io.modelcontextprotocol/serverInfo"] == nil {
			t.Errorf("%s: no serverInfo in _meta", c.method)
		}
	}
}

func TestToolsCallReturnsTheResult(t *testing.T) {
	_, h := started(t)
	_, out := post(t, h, "tools/call", "echo.reverse", `"name":"echo.reverse","arguments":{"text":"héllo"},`)
	result := out["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	if structured["reversed"] != "olléh" {
		t.Fatalf("reversed = %v, want olléh (runes, not bytes)", structured["reversed"])
	}
}

func TestToolsListIsDeterministicAndCacheable(t *testing.T) {
	_, h := started(t)
	seen := map[string]bool{}
	var last map[string]any
	for i := 0; i < 20; i++ {
		_, out := post(t, h, "tools/list", "", "")
		result := out["result"].(map[string]any)
		tools, _ := json.Marshal(result["tools"])
		seen[string(tools)] = true
		last = result
	}
	if len(seen) != 1 {
		t.Fatalf("tools/list produced %d distinct payloads across 20 calls", len(seen))
	}
	if last["ttlMs"] == nil || last["cacheScope"] == nil {
		t.Fatalf("tools/list result lacks ttlMs/cacheScope: %v", last)
	}
}

func TestEveryInvocationIsAudited(t *testing.T) {
	s, h := started(t)
	post(t, h, "tools/call", "echo.reverse", `"name":"echo.reverse","arguments":{"text":"a"},`)
	post(t, h, "tools/call", "echo.reverse", `"name":"echo.reverse","arguments":{"text":"b"},`)
	records := s.Audit().Records()
	if len(records) != 2 {
		t.Fatalf("%d audit record(s) after two invocations, want 2", len(records))
	}
	for _, r := range records {
		if r.ToolName != "echo.reverse" || r.PrincipalID != "anonymous" || r.Outcome != "ok" {
			t.Errorf("unexpected record: %+v", r)
		}
	}
}

func TestAMissingHeaderIsRefusedWith400(t *testing.T) {
	_, h := started(t)
	body := `{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{` + meta + `}}`
	resp, err := http.Post(h.URL+"/mcp", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTP %d, want 400 for a request with no Mcp-Method header", resp.StatusCode)
	}
}

func TestAnUnknownToolIsInvalidParams(t *testing.T) {
	_, h := started(t)
	_, out := post(t, h, "tools/call", "no.such", `"name":"no.such","arguments":{},`)
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != -32602 {
		t.Fatalf("error = %v, want -32602", out["error"])
	}
}

func TestRemovedMethodsAnswerMethodNotFound(t *testing.T) {
	_, h := started(t)
	status, out := post(t, h, "initialize", "", "")
	errObj, _ := out["error"].(map[string]any)
	if status != http.StatusNotFound || errObj == nil || errObj["code"].(float64) != -32601 {
		t.Fatalf("HTTP %d, error %v; want 404 and -32601", status, out["error"])
	}
}
