package otlp_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/patsypppe/sentinel/mcp/example"
	"github.com/patsypppe/sentinel/mcp/otlp"
	"github.com/patsypppe/sentinel/mcp/registry"
	"github.com/patsypppe/sentinel/mcp/server"
)

// A real kit server, the real exporter, and a stand-in collector: the trace a client
// started is the trace the collector receives, and the tool's argument is not in it.
func TestAKitServerExportsTheClientsTraceToACollector(t *testing.T) {
	var mu sync.Mutex
	var received []byte
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, body...)
		mu.Unlock()
	}))
	defer collector.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	exporter, err := otlp.New(collector.URL, "kit-test", log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	exporter.Start(ctx)

	srv, err := server.New(server.Options{
		Info:         example.Info,
		Tools:        []registry.Tool{example.Reverse{}},
		Logger:       log,
		SpanRecorder: exporter.Record,
		Authenticator: server.InsecureAnonymous(registry.Principal{
			TenantID: "t", ID: "p", Scopes: []string{example.Scope},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(srv.Handler())
	defer h.Close()

	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	body := `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"echo.reverse",` +
		`"arguments":{"text":"hunter2"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{},"traceparent":"` + tp + `"}}}`
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "echo.reverse")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	cancel()
	exporter.Wait()

	mu.Lock()
	defer mu.Unlock()
	var doc map[string]any
	if err := json.Unmarshal(received, &doc); err != nil {
		t.Fatalf("collector got %q: %v", received, err)
	}
	text := string(received)
	for _, want := range []string{
		`"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"`,
		`"parentSpanId":"00f067aa0ba902b7"`,
		`"name":"mcp tools/call echo.reverse"`,
		`"service.name"`, "kit-test",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("collector payload lacks %s:\n%s", want, text)
		}
	}
	if strings.Contains(text, "hunter2") {
		t.Error("a tool argument reached the collector")
	}
}
