package otlp

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
	"time"

	"github.com/patsypppe/sentinel/mcp/transport"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type collector struct {
	mu     sync.Mutex
	bodies [][]byte
	status int
}

func (c *collector) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.bodies = append(c.bodies, body)
	status := c.status
	c.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func (c *collector) spans(t *testing.T) []map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, b := range c.bodies {
		var doc struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []map[string]any `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []map[string]any `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("collector received invalid JSON: %v", err)
		}
		for _, rs := range doc.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				out = append(out, ss.Spans...)
			}
		}
	}
	return out
}

func run(t *testing.T, c *collector) (*Exporter, context.CancelFunc) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	t.Cleanup(srv.Close)
	e, err := New(srv.URL, "test-service", quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	return e, cancel
}

func span(name, traceparent string) transport.Span {
	now := time.Now()
	return transport.Span{Name: name, Method: "tools/call", Tool: "echo", Traceparent: traceparent,
		Start: now.Add(-5 * time.Millisecond), End: now}
}

func TestEndpointNormalisationAndTheGRPCPort(t *testing.T) {
	for in, want := range map[string]string{
		"collector:4318":                "http://collector:4318/v1/traces",
		"http://collector:4318":         "http://collector:4318/v1/traces",
		"https://c.example/custom/path": "https://c.example/custom/path",
		"  localhost:4318/v1/traces  ":  "http://localhost:4318/v1/traces",
	} {
		got, err := Endpoint(in)
		if err != nil || got != want {
			t.Errorf("Endpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := Endpoint("otel-collector:4317"); err == nil || !strings.Contains(err.Error(), "gRPC") {
		t.Errorf("the gRPC port was accepted: %v", err)
	}
	for _, bad := range []string{"", "   ", "http://"} {
		if _, err := Endpoint(bad); err == nil {
			t.Errorf("Endpoint(%q) was accepted", bad)
		}
	}
}

func TestAClientsTraceIsContinuedNotReplaced(t *testing.T) {
	c := &collector{}
	e, cancel := run(t, c)
	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	e.Record(span("mcp tools/call echo", tp))
	cancel()
	e.Wait()

	got := c.spans(t)
	if len(got) != 1 {
		t.Fatalf("%d spans", len(got))
	}
	s := got[0]
	if s["traceId"] != "0af7651916cd43dd8448eb211c80319c" || s["parentSpanId"] != "b7ad6b7169203331" {
		t.Errorf("trace not continued: %v", s)
	}
	if id, _ := s["spanId"].(string); len(id) != 16 || id == "b7ad6b7169203331" {
		t.Errorf("spanId = %v: this server's span needs its own id", s["spanId"])
	}
	if s["kind"].(float64) != 2 {
		t.Errorf("kind = %v, want SERVER", s["kind"])
	}
}

func TestWithoutATraceparentANewTraceStartsAndHasNoParent(t *testing.T) {
	c := &collector{}
	e, cancel := run(t, c)
	e.Record(span("a", ""))
	e.Record(span("b", ""))
	cancel()
	e.Wait()
	got := c.spans(t)
	if len(got) != 2 {
		t.Fatalf("%d spans", len(got))
	}
	for _, s := range got {
		if len(s["traceId"].(string)) != 32 {
			t.Errorf("traceId = %v", s["traceId"])
		}
		if _, has := s["parentSpanId"]; has {
			t.Errorf("a new trace has no parent: %v", s)
		}
	}
	if got[0]["traceId"] == got[1]["traceId"] {
		t.Error("two unrelated requests shared a trace")
	}
}

func TestMalformedTraceparentsStartAFreshTrace(t *testing.T) {
	for _, bad := range []string{
		"", "garbage", "00-short-b7ad6b7169203331-01",
		"01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"00-00000000000000000000000000000000-b7ad6b7169203331-01",
		"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
		"00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",
		"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331",
		"00-zzf7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	} {
		if trace, parent := ParseTraceparent(bad); trace != "" || parent != "" {
			t.Errorf("%q was accepted as %q / %q", bad, trace, parent)
		}
	}
}

func TestAnErrorBecomesAnErrorStatusWithTheCode(t *testing.T) {
	c := &collector{}
	e, cancel := run(t, c)
	s := span("x", "")
	s.ErrorCode, s.ErrorMessage = 1007, "scope denied"
	e.Record(s)
	cancel()
	e.Wait()
	got := c.spans(t)[0]
	status := got["status"].(map[string]any)
	if status["code"].(float64) != 2 || status["message"] != "scope denied" {
		t.Errorf("status = %v", status)
	}
	if !strings.Contains(mustJSON(t, got["attributes"]), "1007") {
		t.Errorf("attributes lack the error code: %v", got["attributes"])
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNoArgumentsAndNoPrincipalAreExported(t *testing.T) {
	c := &collector{}
	e, cancel := run(t, c)
	e.Record(span("mcp tools/call echo", ""))
	cancel()
	e.Wait()
	body := string(c.bodies[0])
	for _, forbidden := range []string{"argument", "principal", "token", "authorization"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("the exported span mentions %q", forbidden)
		}
	}
}

func TestAFullQueueDropsAndCountsInsteadOfBlocking(t *testing.T) {
	e, err := New("http://127.0.0.1:1", "svc", quiet())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize+100; i++ { // Start is not called: nothing drains
			e.Record(span("x", ""))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a full queue")
	}
	if e.Dropped() != 100 {
		t.Errorf("dropped = %d, want 100", e.Dropped())
	}
}

func TestADeadCollectorIsSurvivedAndCounted(t *testing.T) {
	e, err := New("http://127.0.0.1:1/v1/traces", "svc", quiet())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	e.Record(span("x", ""))
	cancel()
	e.Wait()
	if e.Exported() != 0 {
		t.Errorf("exported = %d to a collector that does not exist", e.Exported())
	}
}

func TestACollectorThatRefusesIsNotCountedAsAnExport(t *testing.T) {
	c := &collector{status: http.StatusServiceUnavailable}
	e, cancel := run(t, c)
	e.Record(span("x", ""))
	cancel()
	e.Wait()
	if e.Exported() != 0 {
		t.Errorf("exported = %d after a 503", e.Exported())
	}
}

func TestBatchesAreSplitAtTheBatchSize(t *testing.T) {
	c := &collector{}
	e, cancel := run(t, c)
	for i := 0; i < batchSize*2+3; i++ {
		e.Record(span("x", ""))
	}
	cancel()
	e.Wait()
	if len(c.bodies) < 2 {
		t.Errorf("%d request(s) for %d spans: the batch was never split", len(c.bodies), batchSize*2+3)
	}
	if got := len(c.spans(t)); got != batchSize*2+3 {
		t.Errorf("%d spans arrived, want %d", got, batchSize*2+3)
	}
	if e.Exported() != int64(batchSize*2+3) {
		t.Errorf("exported = %d", e.Exported())
	}
}
