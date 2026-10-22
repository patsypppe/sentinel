package posture

import (
	"testing"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/model"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func at(days float64) time.Time { return t0.Add(time.Duration(days * float64(24*time.Hour))) }

func scan(when time.Time, hash string, findings ...model.Finding) model.ScanRun {
	run := model.ScanRun{Target: "t", ScannedAt: when, ManifestHash: hash, Findings: findings}
	for _, f := range findings {
		if f.Accepted {
			run.Accepted++
		} else {
			run.Failing++
		}
	}
	return run
}

func fail(fp, rule string) model.Finding {
	return model.Finding{Fingerprint: fp, RuleID: rule, Severity: "must"}
}

func TestDailyKeepsTheLastScanOfEachDayAndOmitsDaysNobodyScanned(t *testing.T) {
	scans := []model.ScanRun{
		scan(at(0), "", fail("a", "r")),
		scan(at(0).Add(time.Hour), ""), // later the same day: clean
		scan(at(2), "", fail("a", "r")),
	}
	got := Daily(scans, 30*24*time.Hour, at(3))
	if len(got) != 2 {
		t.Fatalf("%d points, want 2 (day 1 has no scan and must not appear as zero): %+v", len(got), got)
	}
	if got[0].Failing != 0 || got[0].Scans != 2 {
		t.Errorf("day 0 = %+v, want the LAST scan of the day (clean) over 2 scans", got[0])
	}
	if got[1].Failing != 1 {
		t.Errorf("day 2 = %+v", got[1])
	}
}

func TestDailyRespectsTheWindowBoundary(t *testing.T) {
	scans := []model.ScanRun{scan(at(-91), ""), scan(at(-89), "")}
	got := Daily(scans, 90*24*time.Hour, t0)
	if len(got) != 1 {
		t.Fatalf("%d points, want 1: a scan 91 days old is outside a 90-day window", len(got))
	}
}

func TestOpenAgeRunsFromFirstSeenFailing(t *testing.T) {
	scans := []model.ScanRun{
		scan(at(0), "", fail("a", "r1")),
		scan(at(10), "", fail("a", "r1"), fail("b", "r2")),
		scan(at(20), "", fail("a", "r1"), fail("b", "r2")),
	}
	got := Open(scans, at(34))
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Fingerprint != "a" || got[0].AgeDays != 34 {
		t.Errorf("oldest = %+v, want a open for 34 days", got[0])
	}
	if got[1].Fingerprint != "b" || got[1].AgeDays != 24 {
		t.Errorf("second = %+v, want b open for 24 days", got[1])
	}
}

func TestAFixedThenRegressedFindingStartsANewAge(t *testing.T) {
	scans := []model.ScanRun{
		scan(at(0), "", fail("a", "r")),
		scan(at(5), ""),
		scan(at(100), "", fail("a", "r")),
	}
	got := Open(scans, at(110))
	if len(got) != 1 || got[0].AgeDays != 10 {
		t.Fatalf("%+v: a finding fixed for 95 days and then reopened is open for 10, not 110", got)
	}
}

func TestRemediationMeasuresFirstFailingToFirstScanWithoutIt(t *testing.T) {
	scans := []model.ScanRun{
		scan(at(0), "", fail("a", "r"), fail("b", "r")),
		scan(at(4), "", fail("b", "r")), // a fixed after 4 days
		scan(at(10), ""),                // b fixed after 10 days
	}
	got := Remediation(scans)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	if got[0].Fixed != 2 || got[0].MeanDays != 7 {
		t.Errorf("%+v, want 2 fixed with mean 7 days", got[0])
	}
}

func TestRemediationCountsReopenings(t *testing.T) {
	scans := []model.ScanRun{
		scan(at(0), "", fail("a", "r")),
		scan(at(1), ""),
		scan(at(2), "", fail("a", "r")),
		scan(at(3), ""),
		scan(at(4), "", fail("a", "r")),
	}
	got := Remediation(scans)
	if got[0].Fixed != 2 || got[0].Reopened != 2 {
		t.Errorf("%+v, want 2 fixed and 2 reopened", got[0])
	}
}

func TestRemediationIgnoresAFindingThatIsStillOpen(t *testing.T) {
	got := Remediation([]model.ScanRun{scan(at(0), "", fail("a", "r")), scan(at(9), "", fail("a", "r"))})
	if len(got) != 0 {
		t.Fatalf("%+v: nothing has been remediated yet, so there is nothing to average", got)
	}
}

func TestDriftIsAChangeOfHashAndAGapIsNotAChange(t *testing.T) {
	scans := []model.ScanRun{
		scan(at(0), "h1"),
		scan(at(1), ""), // unreadable manifest
		scan(at(2), "h1"),
		scan(at(3), "h2"),
	}
	got := Drift(scans)
	if len(got) != 1 || got[0].Before != "h1" || got[0].After != "h2" || !got[0].At.Equal(at(3)) {
		t.Fatalf("%+v, want one event h1 -> h2 at day 3", got)
	}
}

func TestExpiringPutsAStillFailingWaiverFirstAndFlagsTheLapsed(t *testing.T) {
	day := func(n int) time.Time {
		return time.Date(2026, 10, 1+n, 0, 0, 0, 0, time.UTC)
	}
	latest := model.ScanRun{
		Target:   "t",
		Findings: []model.Finding{fail("a", "needs-waiver")},
		Waivers: []model.Waiver{
			{Rule: "soon-but-passing", ExpiresAt: day(3)},
			{Rule: "needs-waiver", ExpiresAt: day(20)},
			{Rule: "lapsed", ExpiresAt: day(-2)},
			{Rule: "far", ExpiresAt: day(200)},
		},
	}
	got := Expiring(latest, t0, 30*24*time.Hour)
	if len(got) != 3 {
		t.Fatalf("%d waivers, want 3 (the far one is outside 30 days): %+v", len(got), got)
	}
	if got[0].Rule != "needs-waiver" || !got[0].StillFailing {
		t.Errorf("first = %+v: a waiver over a still-failing finding must lead", got[0])
	}
	for _, w := range got {
		if w.Rule == "lapsed" && (!w.Expired || w.DaysLeft >= 0) {
			t.Errorf("lapsed = %+v", w)
		}
	}
}

func TestExpiryIsJudgedByTheDateNotTheHour(t *testing.T) {
	latest := model.ScanRun{Waivers: []model.Waiver{{Rule: "r", ExpiresAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}}}
	morning := Expiring(latest, time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC), time.Hour*24)
	evening := Expiring(latest, time.Date(2026, 10, 1, 23, 59, 0, 0, time.UTC), time.Hour*24)
	if len(morning) != 1 || morning[0].Expired || len(evening) != 1 || evening[0].Expired {
		t.Fatalf("a waiver that expires on the 1st is still valid all day on the 1st: %+v %+v", morning, evening)
	}
}

func TestSummarizeCountsAStaleGreenAsStaleNotAsPassing(t *testing.T) {
	now := at(10)
	latest := []model.ScanRun{
		{Target: "ok", Gate: "must", ScannedAt: at(9)},
		{Target: "bad", Gate: "must", GateFailed: true, ScannedAt: at(9), Failing: 3},
		{Target: "old", Gate: "must", ScannedAt: at(1)},
		{Target: "report-only", ScannedAt: at(9)},
	}
	s := Summarize(latest, now, 48*time.Hour)
	if s.Passing != 1 || s.Failing != 1 || s.Stale != 1 || s.Ungated != 1 || s.Targets != 4 || s.TotalFailing != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestMostFailingCountsTargetsNotFindings(t *testing.T) {
	latest := []model.ScanRun{
		{Findings: []model.Finding{fail("1", "r"), fail("2", "r")}},
		{Findings: []model.Finding{fail("3", "r"), fail("4", "other")}},
	}
	got := MostFailing(latest)
	if got[0].RuleID != "r" || got[0].Targets != 2 {
		t.Fatalf("%+v, want r failing on 2 targets even though one target has it twice", got)
	}
}
