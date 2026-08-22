package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

func TestStdioSharesTheDispatchPath(t *testing.T) {
	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	mux := NewMux()
	mux.Handle(envelope.MethodDiscover, DiscoverHandler(info, ""))

	s := NewStdio(mux, info, envelope.NegotiationConfig{
		Supported:     []string{envelope.RevisionCurrent},
		LegacyVersion: envelope.RevisionLegacy,
		AllowLegacy:   true,
	})

	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}` + "\n")
	var out bytes.Buffer
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}

	var resp envelope.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("%v (output was %q)", err, out.String())
	}
	if resp.Error != nil {
		t.Fatalf("stdio server/discover failed: %d %s", resp.Error.Code, resp.Error.Message)
	}

	var res envelope.DiscoverResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	// The envelope must be attached on stdio exactly as it is over HTTP. If it
	// is not, some state was transport-specific.
	if res.ResultType != envelope.ResultComplete {
		t.Fatalf("resultType = %q on stdio", res.ResultType)
	}
	if res.Meta == nil || res.Meta.ServerInfo == nil {
		t.Fatal("stdio result is missing serverInfo")
	}
}
