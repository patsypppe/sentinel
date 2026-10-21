package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/store"
)

const (
	ingestToken = "ingest-secret"
	readToken   = "read-secret"
)

// clock is the injected time, so "open for 34 days" is not at the mercy of today.
var clock = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func newServer(t *testing.T, readTok string) (*httptest.Server, store.Store) {
	t.Helper()
	st := store.NewMemory()
	h, err := New(Config{
		Store: st, IngestToken: ingestToken, ReadToken: readTok,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st
}

func golden(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../model/testdata/report-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// report builds a minimal v2 report for time t with the given failing rules.
func report(target string, at time.Time, manifest string, gateFailed bool, rules ...string) []byte {
	findings := []map[string]any{}
	for _, r := range rules {
		findings = append(findings, map[string]any{
			"ruleId": r, "severity": "must", "outcome": "fail", "fingerprint": target + "|" + r,
			"detail": "detail of " + r, "waivedBy": nil, "baselined": false,
		})
	}
	doc := map[string]any{
		"schemaVersion": 2, "startedAt": float64(at.Unix()), "specRevision": "2026-07-28",
		"target": map[string]any{
			"identity": "name:" + target, "name": target, "endpoint": "https://" + target + "/mcp",
			"manifestHash": manifest,
		},
		"gate":     map[string]any{"selected": "must", "failed": gateFailed},
		"findings": findings,
		"policy":   map[string]any{"waivers": []any{}},
	}
	raw, _ := json.Marshal(doc)
	return raw
}

func do(t *testing.T, method, url, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func publish(t *testing.T, srv *httptest.Server, body []byte) {
	t.Helper()
	if status, out := do(t, "POST", srv.URL+"/api/v1/scans", ingestToken, body); status != 201 {
		t.Fatalf("publish: HTTP %d: %s", status, out)
	}
}

func getJSON(t *testing.T, srv *httptest.Server, path string) map[string]any {
	t.Helper()
	status, out := do(t, "GET", srv.URL+path, readToken, nil)
	if status != 200 {
		t.Fatalf("GET %s: HTTP %d: %s", path, status, out)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("GET %s: not JSON: %s", path, out)
	}
	return v
}

// ------------------------------------------------------------------- auth

func TestAServerWithoutAnIngestTokenWillNotBuild(t *testing.T) {
	if _, err := New(Config{Store: store.NewMemory()}); err == nil {
		t.Fatal("a server that anyone can publish to was accepted")
	}
	if _, err := New(Config{IngestToken: "x"}); err == nil {
		t.Fatal("a server with no store was accepted")
	}
}

func TestIngestRefusesAMissingOrWrongToken(t *testing.T) {
	srv, _ := newServer(t, "")
	for _, token := range []string{"", "wrong", readToken} {
		status, _ := do(t, "POST", srv.URL+"/api/v1/scans", token, golden(t))
		if status != http.StatusUnauthorized {
			t.Errorf("token %q: HTTP %d, want 401", token, status)
		}
	}
}

func TestTheReadTokenCannotPublishAndTheIngestTokenCannotRead(t *testing.T) {
	srv, _ := newServer(t, readToken)
	if status, _ := do(t, "POST", srv.URL+"/api/v1/scans", readToken, golden(t)); status != 401 {
		t.Errorf("the read token published: HTTP %d", status)
	}
	if status, _ := do(t, "GET", srv.URL+"/api/v1/targets", ingestToken, nil); status != 401 {
		t.Errorf("the ingest token read: HTTP %d", status)
	}
	if status, _ := do(t, "GET", srv.URL+"/api/v1/targets", readToken, nil); status != 200 {
		t.Errorf("the read token was refused: HTTP %d", status)
	}
}

func TestReadsAreRefusedWithoutATokenWhenOneIsSet(t *testing.T) {
	srv, _ := newServer(t, readToken)
	for _, path := range []string{"/", "/waivers", "/api/v1/targets", "/api/v1/fleet/summary", "/static/app.css"} {
		if status, _ := do(t, "GET", srv.URL+path, "", nil); status != 401 {
			t.Errorf("GET %s with no token: HTTP %d, want 401", path, status)
		}
	}
}

func TestABrowserCanAuthenticateWithBasicAuth(t *testing.T) {
	srv, _ := newServer(t, readToken)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("anyone", readToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	srv, _ := newServer(t, readToken)
	if status, _ := do(t, "GET", srv.URL+"/healthz", "", nil); status != 200 {
		t.Fatalf("HTTP %d", status)
	}
}

// ----------------------------------------------------------------- ingest

func TestIngestAcceptsTheReportThePythonHarnessWrites(t *testing.T) {
	srv, _ := newServer(t, "")
	status, out := do(t, "POST", srv.URL+"/api/v1/scans", ingestToken, golden(t))
	if status != 201 {
		t.Fatalf("HTTP %d: %s", status, out)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["target"] != "name:broker-prod" {
		t.Errorf("response = %v", got)
	}
}

func TestIngestRejectsABadReportWith400NotA500(t *testing.T) {
	srv, _ := newServer(t, "")
	for name, body := range map[string][]byte{
		"not json":       []byte("{"),
		"old schema":     []byte(`{"schemaVersion":1}`),
		"no target":      []byte(`{"schemaVersion":2,"target":{}}`),
		"unknown result": []byte(`{"schemaVersion":2,"target":{"identity":"x"},"findings":[{"ruleId":"r","outcome":"?"}]}`),
	} {
		status, out := do(t, "POST", srv.URL+"/api/v1/scans", ingestToken, body)
		if status != http.StatusBadRequest {
			t.Errorf("%s: HTTP %d: %s", name, status, out)
		}
	}
}

func TestIngestRefusesAnOversizedBody(t *testing.T) {
	srv, _ := newServer(t, "")
	big := bytes.Repeat([]byte("x"), MaxReportBytes+1)
	if status, _ := do(t, "POST", srv.URL+"/api/v1/scans", ingestToken, big); status != 413 {
		t.Fatalf("HTTP %d, want 413", status)
	}
}

func TestPublishingTheSameScanTwiceCountsItOnce(t *testing.T) {
	srv, st := newServer(t, readToken)
	at := clock.Add(-time.Hour)
	body := report("a", at, "h1", true, "r1")
	publish(t, srv, body)
	publish(t, srv, body)
	scans, _ := st.Scans(context.Background(), "name:a", at.Add(-time.Hour))
	if len(scans) != 1 {
		t.Fatalf("%d scans after a retried publish, want 1", len(scans))
	}
}

// ------------------------------------------------------------------ reads

func TestTargetsListTheLatestVerdictOfEach(t *testing.T) {
	srv, _ := newServer(t, readToken)
	publish(t, srv, report("a", clock.Add(-2*time.Hour), "h", true, "r1"))
	publish(t, srv, report("a", clock.Add(-time.Hour), "h", false)) // fixed
	publish(t, srv, report("b", clock.Add(-time.Hour), "h", true, "r2", "r3"))
	got := getJSON(t, srv, "/api/v1/targets")["targets"].([]any)
	status := map[string]string{}
	failing := map[string]float64{}
	for _, row := range got {
		r := row.(map[string]any)
		status[r["name"].(string)] = r["status"].(string)
		failing[r["name"].(string)] = r["failing"].(float64)
	}
	if status["a"] != "passing" || status["b"] != "failing" || failing["b"] != 2 {
		t.Fatalf("status = %v failing = %v", status, failing)
	}
}

func TestAnOldGreenIsStaleNotPassing(t *testing.T) {
	srv, _ := newServer(t, readToken)
	publish(t, srv, report("old", clock.Add(-10*24*time.Hour), "h", false))
	got := getJSON(t, srv, "/api/v1/targets")["targets"].([]any)[0].(map[string]any)
	if got["status"] != "stale" {
		t.Fatalf("status = %v: a ten-day-old pass is not a current one", got["status"])
	}
}

func TestPostureAnswersHowLongAFindingHasBeenOpen(t *testing.T) {
	srv, _ := newServer(t, readToken)
	publish(t, srv, report("a", clock.AddDate(0, 0, -34), "h", true, "r1"))
	publish(t, srv, report("a", clock.AddDate(0, 0, -10), "h", true, "r1", "r2"))
	publish(t, srv, report("a", clock.Add(-time.Hour), "h", true, "r1", "r2"))
	got := getJSON(t, srv, "/api/v1/targets/a/posture?window=90d")
	open := got["open"].([]any)
	if len(open) != 2 {
		t.Fatalf("open = %v", open)
	}
	first := open[0].(map[string]any)
	if first["ruleId"] != "r1" || first["ageDays"].(float64) != 34 {
		t.Errorf("oldest = %v, want r1 open 34 days", first)
	}
	if len(got["daily"].([]any)) != 3 {
		t.Errorf("daily = %v", got["daily"])
	}
}

func TestPostureWindowIsParsedAndValidated(t *testing.T) {
	srv, _ := newServer(t, readToken)
	publish(t, srv, report("a", clock.Add(-time.Hour), "h", false))
	if status, _ := do(t, "GET", srv.URL+"/api/v1/targets/a/posture?window=banana", readToken, nil); status != 400 {
		t.Errorf("a bad window: HTTP %d, want 400", status)
	}
	if status, _ := do(t, "GET", srv.URL+"/api/v1/targets/a/posture?window=7d", readToken, nil); status != 200 {
		t.Errorf("7d: HTTP %d", status)
	}
	if status, _ := do(t, "GET", srv.URL+"/api/v1/targets/nobody/posture", readToken, nil); status != 404 {
		t.Errorf("an unknown target: HTTP %d, want 404", status)
	}
}

func TestADriftEventIsRecordedWhenTheManifestHashChanges(t *testing.T) {
	srv, _ := newServer(t, readToken)
	publish(t, srv, report("a", clock.AddDate(0, 0, -3), "hash-one", false))
	publish(t, srv, report("a", clock.AddDate(0, 0, -2), "hash-one", false))
	publish(t, srv, report("a", clock.AddDate(0, 0, -1), "hash-two", false))
	got := getJSON(t, srv, "/api/v1/targets/a/drift")["drift"].([]any)
	if len(got) != 1 {
		t.Fatalf("drift = %v, want one event", got)
	}
	ev := got[0].(map[string]any)
	if ev["before"] != "hash-one" || ev["after"] != "hash-two" {
		t.Fatalf("event = %v", ev)
	}
}

func TestExpiringWaiversListsAStillFailingOneFirst(t *testing.T) {
	srv, _ := newServer(t, readToken)
	soon := clock.AddDate(0, 0, 5).Format("2006-01-02")
	later := clock.AddDate(0, 0, 25).Format("2006-01-02")
	doc := map[string]any{
		"schemaVersion": 2, "startedAt": float64(clock.Add(-time.Hour).Unix()),
		"target": map[string]any{"identity": "name:a", "name": "a"},
		"findings": []map[string]any{{
			"ruleId": "needs-it", "severity": "must", "outcome": "fail", "fingerprint": "f",
			"waivedBy": map[string]any{"rule": "needs-it"}, "baselined": false,
		}},
		"policy": map[string]any{"waivers": []map[string]any{
			{"rule": "idle", "reason": "not failing any more", "expiresAt": soon},
			{"rule": "needs-it", "reason": "migration window", "expiresAt": later},
		}},
	}
	raw, _ := json.Marshal(doc)
	publish(t, srv, raw)
	got := getJSON(t, srv, "/api/v1/waivers/expiring?within=30d")["waivers"].([]any)
	if len(got) != 2 {
		t.Fatalf("waivers = %v", got)
	}
	first := got[0].(map[string]any)
	if first["rule"] != "needs-it" || first["stillFailing"] != true {
		t.Fatalf("first = %v: a waiver over a still-failing finding must lead", first)
	}
	narrow := getJSON(t, srv, "/api/v1/waivers/expiring?within=10d")["waivers"].([]any)
	if len(narrow) != 1 {
		t.Fatalf("within 10d = %v, want only the one expiring in 5", narrow)
	}
}

func TestFleetSummaryCountsEachState(t *testing.T) {
	srv, _ := newServer(t, readToken)
	publish(t, srv, report("good", clock.Add(-time.Hour), "h", false))
	publish(t, srv, report("bad", clock.Add(-time.Hour), "h", true, "r"))
	publish(t, srv, report("old", clock.Add(-9*24*time.Hour), "h", false))
	got := getJSON(t, srv, "/api/v1/fleet/summary")
	sum := got["summary"].(map[string]any)
	if sum["passing"] != 1.0 || sum["failing"] != 1.0 || sum["stale"] != 1.0 || sum["targets"] != 3.0 {
		t.Fatalf("summary = %v", sum)
	}
	most := got["mostFailing"].([]any)
	if len(most) != 1 || most[0].(map[string]any)["ruleId"] != "r" {
		t.Fatalf("mostFailing = %v", most)
	}
}

// -------------------------------------------------------------- dashboard

func TestEveryResponseCarriesAStrictContentSecurityPolicy(t *testing.T) {
	srv, _ := newServer(t, "")
	publish(t, srv, report("a", clock.Add(-time.Hour), "h", false))
	for _, path := range []string{"/", "/waivers", "/targets/a", "/api/v1/targets", "/healthz", "/static/app.css"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") ||
			strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", path)
		}
	}
}

func TestADashboardPageMakesNoExternalRequest(t *testing.T) {
	srv, _ := newServer(t, "")
	publish(t, srv, report("a", clock.Add(-time.Hour), "h", true, "r"))
	for _, path := range []string{"/", "/waivers", "/targets/a"} {
		_, out := do(t, "GET", srv.URL+path, "", nil)
		page := string(out)
		for _, banned := range []string{"<script", "http://", "https://", "@import", "<iframe", "<img"} {
			// A target endpoint is shown as text, so https:// may appear in content;
			// what must not appear is a tag or attribute that would FETCH one.
			if banned == "https://" || banned == "http://" {
				if strings.Contains(page, `src="http`) || strings.Contains(page, `href="http`) {
					t.Errorf("%s loads or links an external URL", path)
				}
				continue
			}
			if strings.Contains(page, banned) {
				t.Errorf("%s contains %q", path, banned)
			}
		}
		if strings.Contains(page, "style=") {
			t.Errorf("%s uses an inline style, which the CSP forbids", path)
		}
	}
}

func TestAHostileTargetNameIsEscapedNotExecuted(t *testing.T) {
	srv, _ := newServer(t, "")
	hostile := `<script>alert(1)</script>`
	doc := map[string]any{
		"schemaVersion": 2, "startedAt": float64(clock.Add(-time.Hour).Unix()),
		"target": map[string]any{"identity": "name:x", "name": hostile, "endpoint": "https://x/" + hostile},
		"findings": []map[string]any{{
			"ruleId": hostile, "severity": "must", "outcome": "fail", "fingerprint": "f",
			"detail": hostile, "waivedBy": nil, "baselined": false,
		}},
		"policy": map[string]any{"waivers": []any{}},
	}
	raw, _ := json.Marshal(doc)
	publish(t, srv, raw)
	for _, path := range []string{"/", "/targets/name:x"} {
		_, out := do(t, "GET", srv.URL+path, "", nil)
		if strings.Contains(string(out), hostile) {
			t.Errorf("%s: the hostile string appears unescaped", path)
		}
	}
}

func TestTheFleetPageShowsTheTargetAndAnEmptyFleetSaysHowToPublish(t *testing.T) {
	srv, _ := newServer(t, "")
	_, empty := do(t, "GET", srv.URL+"/", "", nil)
	if !strings.Contains(string(empty), "sentinel scan --publish") {
		t.Error("an empty fleet should say how to publish")
	}
	publish(t, srv, report("broker-prod", clock.Add(-3*time.Hour), "h", true, "r1"))
	_, page := do(t, "GET", srv.URL+"/", "", nil)
	for _, want := range []string{"broker-prod", "failing", "3 hours ago", "r1"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("fleet page lacks %q", want)
		}
	}
}

func TestATargetPageDrawsTheChartAndListsWhatIsOpen(t *testing.T) {
	srv, _ := newServer(t, "")
	publish(t, srv, report("a", clock.AddDate(0, 0, -3), "h", true, "r1"))
	publish(t, srv, report("a", clock.Add(-time.Hour), "h", true, "r1"))
	_, page := do(t, "GET", srv.URL+"/targets/a", "", nil)
	for _, want := range []string{"<svg", "r1", "Open findings", "since "} {
		if !strings.Contains(string(page), want) {
			t.Errorf("target page lacks %q:\n%s", want, page)
		}
	}
}

func TestAnUnknownTargetPageIs404(t *testing.T) {
	srv, _ := newServer(t, "")
	if status, _ := do(t, "GET", srv.URL+"/targets/nobody", "", nil); status != 404 {
		t.Fatalf("HTTP %d", status)
	}
}

func TestDurationParsing(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 5 * time.Hour, "90d": 90 * 24 * time.Hour, "12h": 12 * time.Hour, "30m": 30 * time.Minute,
	} {
		got, err := parseDuration(in, 5*time.Hour)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0d", "-3d", "banana", "9999d", "d", "1.5d"} {
		if _, err := parseDuration(bad, time.Hour); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
