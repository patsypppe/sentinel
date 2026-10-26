// Package otlp exports request spans to an OpenTelemetry collector over OTLP/HTTP with
// JSON encoding.
//
// It is hand-written, about two hundred lines, rather than the OpenTelemetry SDK, for
// one reason: the SDK's OTLP exporters pull in gRPC and protobuf, and a server kit
// whose dependency graph quadruples to emit one kind of span is paying for generality
// it does not use. The wire format is the standard one -- a collector cannot tell the
// difference -- and the cost is that this exports spans and nothing else.
//
// Four properties matter more than the encoding:
//
//   - The client's trace is CONTINUED. A request carrying a W3C traceparent in _meta
//     gets a span whose trace id is the client's and whose parent is the client's span,
//     so a trace joins across the client and this server. Without one, a new trace.
//   - Recording never blocks a request. Spans go on a bounded queue and a full queue
//     drops the span and counts it; tracing is never worth a slow tool call.
//   - A collector that is down is a logged warning, not an error that reaches a caller.
//   - It carries no argument values and no principal (see transport.Span).
package otlp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patsypppe/sentinel/mcp/transport"
)

const (
	queueSize    = 2048
	batchSize    = 64
	flushEvery   = 2 * time.Second
	postTimeout  = 5 * time.Second
	scopeName    = "github.com/patsypppe/sentinel/mcp"
	spanKindServ = 2
)

// Exporter batches spans and posts them to a collector.
type Exporter struct {
	endpoint string
	service  string
	client   *http.Client
	log      *slog.Logger
	queue    chan transport.Span

	dropped  atomic.Int64
	exported atomic.Int64
	wg       sync.WaitGroup
}

// Endpoint turns BROKER_OTEL_ENDPOINT into the URL spans are posted to. It accepts a
// host:port or a URL; a bare host:port is http, and the path defaults to /v1/traces.
//
// Port 4317 is refused, because it is the OTLP/gRPC port and this exporter speaks
// OTLP/HTTP. Sending JSON to a gRPC port would fail in a way that looks like a network
// problem, so the mistake is named at startup instead.
func Endpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("otlp: endpoint is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("otlp: %q is not a host:port or URL", raw)
	}
	if u.Port() == "4317" {
		return "", fmt.Errorf("otlp: %s is the OTLP/gRPC port, and this exporter speaks OTLP/HTTP; "+
			"use the collector's HTTP port, normally 4318", u.Host)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/traces"
	}
	return u.String(), nil
}

// New builds an exporter. Call Start to run it and pass Record as the span recorder.
func New(endpoint, service string, log *slog.Logger) (*Exporter, error) {
	target, err := Endpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Exporter{
		endpoint: target, service: service, log: log,
		client: &http.Client{Timeout: postTimeout},
		queue:  make(chan transport.Span, queueSize),
	}, nil
}

// Record enqueues a span. It never blocks.
func (e *Exporter) Record(s transport.Span) {
	select {
	case e.queue <- s:
	default:
		e.dropped.Add(1)
	}
}

// Dropped is how many spans were discarded because the queue was full.
func (e *Exporter) Dropped() int64 { return e.dropped.Load() }

// Exported is how many spans a collector accepted.
func (e *Exporter) Exported() int64 { return e.exported.Load() }

// Start begins exporting in the background until ctx is cancelled, then drains what is
// queued. The wait-group is incremented HERE, before the goroutine exists: doing it
// inside the goroutine would let Wait return before the exporter had started, and a
// shutdown would then lose every span still queued.
func (e *Exporter) Start(ctx context.Context) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.run(ctx)
	}()
}

func (e *Exporter) run(ctx context.Context) {
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	batch := make([]transport.Span, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		e.send(batch)
		batch = batch[:0]
	}
	for {
		select {
		case s := <-e.queue:
			batch = append(batch, s)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case s := <-e.queue:
					batch = append(batch, s)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// Wait blocks until the exporter started by Start has drained and stopped.
func (e *Exporter) Wait() { e.wg.Wait() }

func (e *Exporter) send(spans []transport.Span) {
	body, err := json.Marshal(e.payload(spans))
	if err != nil {
		e.log.Warn("otlp: could not encode spans", "err", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		e.log.Warn("otlp: bad request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		e.log.Warn("otlp: collector unreachable; spans dropped", "count", len(spans), "err", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		e.log.Warn("otlp: collector refused spans", "status", resp.StatusCode, "count", len(spans))
		return
	}
	e.exported.Add(int64(len(spans)))
}

// ---- encoding (OTLP/JSON: ids are hex strings, times are decimal-string nanoseconds)

type kv struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func str(k, v string) kv { return kv{k, map[string]string{"stringValue": v}} }
func num(k string, v int) kv {
	return kv{k, map[string]string{"intValue": strconv.Itoa(v)}}
}

func (e *Exporter) payload(spans []transport.Span) map[string]any {
	out := make([]map[string]any, 0, len(spans))
	for _, s := range spans {
		traceID, parentID := ParseTraceparent(s.Traceparent)
		if traceID == "" {
			traceID = randomHex(16)
		}
		attrs := []kv{str("mcp.method", s.Method)}
		if s.Tool != "" {
			attrs = append(attrs, str("mcp.tool", s.Tool))
		}
		status := map[string]any{"code": 1}
		if s.ErrorCode != 0 {
			attrs = append(attrs, num("rpc.jsonrpc.error_code", s.ErrorCode))
			status = map[string]any{"code": 2, "message": s.ErrorMessage}
		}
		span := map[string]any{
			"traceId": traceID, "spanId": randomHex(8), "name": s.Name, "kind": spanKindServ,
			"startTimeUnixNano": strconv.FormatInt(s.Start.UnixNano(), 10),
			"endTimeUnixNano":   strconv.FormatInt(s.End.UnixNano(), 10),
			"attributes":        attrs, "status": status,
		}
		if parentID != "" {
			span["parentSpanId"] = parentID
		}
		out = append(out, span)
	}
	return map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   map[string]any{"attributes": []kv{str("service.name", e.service)}},
		"scopeSpans": []any{map[string]any{"scope": map[string]string{"name": scopeName}, "spans": out}},
	}}}
}

// ParseTraceparent reads a W3C traceparent ("00-<trace>-<parent>-<flags>"). It returns
// empty strings for anything malformed, including the all-zero ids the specification
// forbids, so a hostile or broken header starts a fresh trace instead of poisoning one.
func ParseTraceparent(tp string) (traceID, parentID string) {
	parts := strings.Split(strings.TrimSpace(tp), "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return "", ""
	}
	for _, p := range parts[1:] {
		if _, err := hex.DecodeString(p); err != nil || strings.ToLower(p) != p {
			return "", ""
		}
	}
	if strings.Trim(parts[1], "0") == "" || strings.Trim(parts[2], "0") == "" {
		return "", ""
	}
	return parts[1], parts[2]
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on a supported platform; a non-zero constant keeps
		// the id valid (all-zero is forbidden) if it ever did.
		for i := range b {
			b[i] = byte(i + 1)
		}
	}
	return hex.EncodeToString(b)
}
