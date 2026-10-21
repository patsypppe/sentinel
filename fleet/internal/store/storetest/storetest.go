// Package storetest is the contract every store.Store must satisfy.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/model"
	"github.com/patsypppe/sentinel/fleet/internal/store"
)

var (
	base = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	// A waiver expires on a date, as the harness writes it: midnight UTC.
	expiry = time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
)

func run(target string, at time.Time, findings ...model.Finding) model.ScanRun {
	r := model.ScanRun{
		Target: target, Name: target, Endpoint: "https://" + target + "/mcp", ScannedAt: at,
		SpecRevision: "2026-07-28", ManifestHash: "h-" + target, Gate: "must",
		Passing: 40, Failing: len(findings), Indeterminate: 5, NotApplicable: 6, Findings: findings,
		Waivers: []model.Waiver{{
			Rule: "MCP/2026-07-28/MUST/x", Reason: "because", ExpiresAt: expiry,
			ApprovedBy: "sec@example.com",
		}},
	}
	return r
}

func finding(fp string) model.Finding {
	return model.Finding{Fingerprint: fp, RuleID: "MCP/2026-07-28/MUST/" + fp, Severity: "must", Detail: "d"}
}

// Run exercises a store. `fresh` must return an empty store each time it is called.
func Run(t *testing.T, fresh func(t *testing.T) store.Store) {
	t.Helper()
	ctx := context.Background()

	t.Run("a scan round-trips with its findings and waivers", func(t *testing.T) {
		s := fresh(t)
		id, err := s.SaveScan(ctx, run("a", base, finding("f1"), finding("f2")))
		if err != nil || id == 0 {
			t.Fatalf("id = %d err = %v", id, err)
		}
		got, err := s.Scans(ctx, "a", base.Add(-time.Hour))
		if err != nil || len(got) != 1 {
			t.Fatalf("got %d err %v", len(got), err)
		}
		r := got[0]
		if r.ID != id || r.Name != "a" || r.Failing != 2 || r.ManifestHash != "h-a" || r.Gate != "must" {
			t.Errorf("scan = %+v", r)
		}
		if len(r.Findings) != 2 || len(r.Waivers) != 1 || r.Waivers[0].ApprovedBy != "sec@example.com" {
			t.Errorf("findings = %+v waivers = %+v", r.Findings, r.Waivers)
		}
		if !r.ScannedAt.Equal(base) {
			t.Errorf("scannedAt = %v, want %v", r.ScannedAt, base)
		}
		if !r.Waivers[0].ExpiresAt.Equal(expiry) {
			t.Errorf("waiver expiry = %v: a date must survive as a date", r.Waivers[0].ExpiresAt)
		}
	})

	t.Run("saving the same scan twice records it once", func(t *testing.T) {
		s := fresh(t)
		first, _ := s.SaveScan(ctx, run("a", base, finding("f1")))
		second, err := s.SaveScan(ctx, run("a", base, finding("f1")))
		if err != nil || second != first {
			t.Fatalf("second id = %d err = %v, want %d", second, err, first)
		}
		got, _ := s.Scans(ctx, "a", base.Add(-time.Hour))
		if len(got) != 1 {
			t.Fatalf("%d scans after a retried publish, want 1", len(got))
		}
	})

	t.Run("scans come back oldest first and respect since", func(t *testing.T) {
		s := fresh(t)
		for _, d := range []int{3, 1, 2} {
			_, _ = s.SaveScan(ctx, run("a", base.AddDate(0, 0, d)))
		}
		got, _ := s.Scans(ctx, "a", base.AddDate(0, 0, 2))
		if len(got) != 2 || !got[0].ScannedAt.Before(got[1].ScannedAt) {
			t.Fatalf("got %+v", got)
		}
		if got[0].ScannedAt.Day() != base.AddDate(0, 0, 2).Day() {
			t.Errorf("since is inclusive: first = %v", got[0].ScannedAt)
		}
	})

	t.Run("scans of other targets are not returned", func(t *testing.T) {
		s := fresh(t)
		_, _ = s.SaveScan(ctx, run("a", base))
		_, _ = s.SaveScan(ctx, run("b", base))
		got, _ := s.Scans(ctx, "a", base.Add(-time.Hour))
		if len(got) != 1 || got[0].Target != "a" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("latest per target is the most recent of each, ordered by target", func(t *testing.T) {
		s := fresh(t)
		_, _ = s.SaveScan(ctx, run("b", base))
		_, _ = s.SaveScan(ctx, run("a", base))
		_, _ = s.SaveScan(ctx, run("a", base.AddDate(0, 0, 5), finding("new")))
		got, err := s.LatestPerTarget(ctx)
		if err != nil || len(got) != 2 {
			t.Fatalf("got %d err %v", len(got), err)
		}
		if got[0].Target != "a" || got[1].Target != "b" {
			t.Errorf("order = %s, %s", got[0].Target, got[1].Target)
		}
		if got[0].Failing != 1 || len(got[0].Findings) != 1 {
			t.Errorf("a's latest should be the newer scan: %+v", got[0])
		}
	})

	t.Run("an empty store returns empty, not an error", func(t *testing.T) {
		s := fresh(t)
		latest, err := s.LatestPerTarget(ctx)
		if err != nil || len(latest) != 0 {
			t.Fatalf("latest = %v err = %v", latest, err)
		}
		scans, err := s.Scans(ctx, "nobody", base)
		if err != nil || len(scans) != 0 {
			t.Fatalf("scans = %v err = %v", scans, err)
		}
	})

	t.Run("a stored scan is not changed by changing the one passed in", func(t *testing.T) {
		s := fresh(t)
		in := run("a", base, finding("f1"))
		_, _ = s.SaveScan(ctx, in)
		in.Findings[0].RuleID = "mutated"
		got, _ := s.Scans(ctx, "a", base.Add(-time.Hour))
		if got[0].Findings[0].RuleID == "mutated" {
			t.Fatal("the store kept a reference to the caller's slice")
		}
	})
}
