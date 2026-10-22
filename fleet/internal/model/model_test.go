package model

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func golden(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/report-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParsesTheReportThePythonHarnessActuallyWrites(t *testing.T) {
	run, err := ParseReport(golden(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if run.Target != "name:broker-prod" || run.Name != "broker-prod" {
		t.Errorf("target = %q name = %q", run.Target, run.Name)
	}
	if run.Gate != "must" || !run.GateFailed {
		t.Errorf("gate = %q failed = %v", run.Gate, run.GateFailed)
	}
	if len(run.ManifestHash) != 64 {
		t.Errorf("manifest hash = %q", run.ManifestHash)
	}
	// 1 failing, 1 waived, 50 baselined: failing is what gates, the rest is accepted.
	if run.Failing != 1 || run.Accepted != 51 {
		t.Errorf("failing = %d accepted = %d, want 1 and 51", run.Failing, run.Accepted)
	}
	if run.Passing != 5 || run.Indeterminate != 5 || run.NotApplicable != 6 {
		t.Errorf("counts = %+v", run)
	}
	if len(run.Findings) != 52 {
		t.Errorf("%d findings stored, want the 52 failing ones and none of the passes", len(run.Findings))
	}
	for _, f := range run.Findings {
		if len(f.Fingerprint) != 64 || f.RuleID == "" {
			t.Fatalf("bad finding %+v", f)
		}
	}
	if len(run.Waivers) != 1 || run.Waivers[0].ApprovedBy != "security@example.com" {
		t.Errorf("waivers = %+v", run.Waivers)
	}
	if run.ScannedAt.Year() < 2026 {
		t.Errorf("scannedAt = %v: startedAt was not read", run.ScannedAt)
	}
}

func TestARefusalIsABadReportNotAServerError(t *testing.T) {
	for name, body := range map[string]string{
		"not json":        `{`,
		"wrong schema":    `{"schemaVersion":1}`,
		"no identity":     `{"schemaVersion":2,"target":{"identity":""}}`,
		"unknown outcome": `{"schemaVersion":2,"target":{"identity":"x"},"findings":[{"ruleId":"r","outcome":"maybe"}]}`,
		"bad waiver date": `{"schemaVersion":2,"target":{"identity":"x"},"policy":{"waivers":[{"rule":"r","expiresAt":"soon"}]}}`,
	} {
		_, err := ParseReport([]byte(body), now)
		if !errors.Is(err, ErrBadReport) {
			t.Errorf("%s: err = %v, want ErrBadReport", name, err)
		}
	}
}

func TestTheSchemaRefusalSaysWhatToDo(t *testing.T) {
	_, err := ParseReport([]byte(`{"schemaVersion":1}`), now)
	if err == nil || !strings.Contains(err.Error(), "--schema-version 2") {
		t.Fatalf("err = %v", err)
	}
}

func TestAReportWithNoStartTimeIsStampedByTheInjectedClock(t *testing.T) {
	run, err := ParseReport([]byte(`{"schemaVersion":2,"target":{"identity":"x"}}`), now)
	if err != nil || !run.ScannedAt.Equal(now) {
		t.Fatalf("run = %+v err = %v", run, err)
	}
}

func TestAWaiverOnlyCountsAsAcceptedWhenItWasApplied(t *testing.T) {
	body := `{"schemaVersion":2,"target":{"identity":"x"},"findings":[
	  {"ruleId":"a","outcome":"fail","fingerprint":"1","waivedBy":null,"baselined":false},
	  {"ruleId":"b","outcome":"fail","fingerprint":"2","waivedBy":{"rule":"b"},"baselined":false},
	  {"ruleId":"c","outcome":"fail","fingerprint":"3","waivedBy":null,"baselined":true}]}`
	run, err := ParseReport([]byte(body), now)
	if err != nil || run.Failing != 1 || run.Accepted != 2 {
		t.Fatalf("run = %+v err = %v", run, err)
	}
}

func TestDisplayNameFallsBackToTheIdentity(t *testing.T) {
	if (ScanRun{Target: "http://a/mcp"}).DisplayName() != "http://a/mcp" {
		t.Fatal("no name should show the identity")
	}
	if (ScanRun{Target: "http://a/mcp", Name: "prod"}).DisplayName() != "prod" {
		t.Fatal("a name wins")
	}
}
