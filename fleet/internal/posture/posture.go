// Package posture computes what a single scan cannot: change over time.
//
// Everything here is a pure function of scans and a clock. No database, no HTTP, no
// time.Now. That is what makes "this finding has been open for 34 days" a thing that
// can be tested at a boundary instead of hoped for.
package posture

import (
	"sort"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/model"
)

const day = 24 * time.Hour

// DayPoint is a target's state at the end of one UTC day: the last scan of that day.
type DayPoint struct {
	Date          string `json:"date"`
	Scans         int    `json:"scans"`
	Failing       int    `json:"failing"`
	Accepted      int    `json:"accepted"`
	Indeterminate int    `json:"indeterminate"`
	GateFailed    bool   `json:"gateFailed"`
}

// Daily is the per-day series over [now-window, now], oldest first. Days with no scan
// are absent rather than zero: a day nobody scanned is unknown, not clean, and a chart
// that drew it as zero would be reporting a good number it did not measure.
func Daily(scans []model.ScanRun, window time.Duration, now time.Time) []DayPoint {
	since := now.Add(-window)
	last := map[string]model.ScanRun{}
	count := map[string]int{}
	for _, s := range scans {
		if s.ScannedAt.Before(since) || s.ScannedAt.After(now) {
			continue
		}
		d := s.ScannedAt.UTC().Format("2006-01-02")
		count[d]++
		if cur, ok := last[d]; !ok || !s.ScannedAt.Before(cur.ScannedAt) {
			last[d] = s
		}
	}
	dates := make([]string, 0, len(last))
	for d := range last {
		dates = append(dates, d)
	}
	sort.Strings(dates)
	out := make([]DayPoint, 0, len(dates))
	for _, d := range dates {
		s := last[d]
		out = append(out, DayPoint{
			Date: d, Scans: count[d], Failing: s.Failing, Accepted: s.Accepted,
			Indeterminate: s.Indeterminate, GateFailed: s.GateFailed,
		})
	}
	return out
}

// OpenFinding is a failing finding in the latest scan, and how long it has been failing.
type OpenFinding struct {
	Fingerprint string    `json:"fingerprint"`
	RuleID      string    `json:"ruleId"`
	Severity    string    `json:"severity"`
	Accepted    bool      `json:"accepted"`
	FirstSeen   time.Time `json:"firstSeen"`
	AgeDays     int       `json:"ageDays"`
}

// Open lists the findings failing in the latest scan, with the time each was first
// seen failing. A finding that was fixed and then regressed starts a new age: the
// clock restarts when it reopens, because "open for 200 days" for something fixed
// for 150 of them would be a false statement about the target.
func Open(scans []model.ScanRun, now time.Time) []OpenFinding {
	ordered := byTime(scans)
	if len(ordered) == 0 {
		return nil
	}
	latest := ordered[len(ordered)-1]
	since := map[string]time.Time{}
	for _, s := range ordered {
		failing := failingSet(s)
		for fp := range since {
			if !failing[fp] {
				delete(since, fp) // fixed: the next failure is a new one
			}
		}
		for fp := range failing {
			if _, ok := since[fp]; !ok {
				since[fp] = s.ScannedAt
			}
		}
	}
	out := make([]OpenFinding, 0, len(latest.Findings))
	for _, f := range latest.Findings {
		first := since[f.Fingerprint]
		out = append(out, OpenFinding{
			Fingerprint: f.Fingerprint, RuleID: f.RuleID, Severity: f.Severity,
			Accepted: f.Accepted, FirstSeen: first, AgeDays: int(now.Sub(first) / day),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgeDays != out[j].AgeDays {
			return out[i].AgeDays > out[j].AgeDays
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// RuleRemediation is how long findings of one rule take to be fixed.
type RuleRemediation struct {
	RuleID string `json:"ruleId"`
	// Fixed is how many findings of this rule were seen failing and later seen not.
	Fixed int `json:"fixed"`
	// MeanDays is the mean time from first failing to first scan without it. It is a
	// measure of scan cadence as much as of the team: a fix is only observed when the
	// next scan runs, so it is an upper bound by up to one scan interval.
	MeanDays float64 `json:"meanDays"`
	// Reopened is how many times a fixed finding came back.
	Reopened int `json:"reopened"`
}

// Remediation computes time to remediation per rule across the given scans.
func Remediation(scans []model.ScanRun) []RuleRemediation {
	type acc struct {
		fixed, reopened int
		total           time.Duration
	}
	byRule := map[string]*acc{}
	get := func(rule string) *acc {
		if byRule[rule] == nil {
			byRule[rule] = &acc{}
		}
		return byRule[rule]
	}

	open := map[string]time.Time{} // fingerprint -> first failing
	ruleOf := map[string]string{}  // fingerprint -> rule
	everFixed := map[string]bool{} // fingerprint fixed at least once
	for _, s := range byTime(scans) {
		failing := failingSet(s)
		for _, f := range s.Findings {
			ruleOf[f.Fingerprint] = f.RuleID
		}
		for fp, first := range open {
			if !failing[fp] {
				a := get(ruleOf[fp])
				a.fixed++
				a.total += s.ScannedAt.Sub(first)
				everFixed[fp] = true
				delete(open, fp)
			}
		}
		for fp := range failing {
			if _, ok := open[fp]; !ok {
				if everFixed[fp] {
					get(ruleOf[fp]).reopened++
				}
				open[fp] = s.ScannedAt
			}
		}
	}

	out := make([]RuleRemediation, 0, len(byRule))
	for rule, a := range byRule {
		r := RuleRemediation{RuleID: rule, Fixed: a.fixed, Reopened: a.reopened}
		if a.fixed > 0 {
			r.MeanDays = float64(a.total) / float64(a.fixed) / float64(day)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// DriftEvent is a change in a target's tool manifest between two consecutive scans.
type DriftEvent struct {
	At     time.Time `json:"at"`
	Before string    `json:"before"`
	After  string    `json:"after"`
}

// Drift lists every point where the manifest hash changed. The service knows THAT the
// manifest changed and when; `sentinel diff` against a snapshot says WHAT changed and
// how severe it is. A scan with no hash (an unreadable manifest) neither starts nor
// ends a drift event: it is a gap, not a change.
func Drift(scans []model.ScanRun) []DriftEvent {
	var out []DriftEvent
	prev := ""
	for _, s := range byTime(scans) {
		if s.ManifestHash == "" {
			continue
		}
		if prev != "" && s.ManifestHash != prev {
			out = append(out, DriftEvent{At: s.ScannedAt, Before: prev, After: s.ManifestHash})
		}
		prev = s.ManifestHash
	}
	return out
}

// ExpiringWaiver is a waiver about to lapse, and whether it still matters.
type ExpiringWaiver struct {
	Target     string    `json:"target"`
	Rule       string    `json:"rule"`
	Reason     string    `json:"reason"`
	ApprovedBy string    `json:"approvedBy,omitempty"`
	ExpiresAt  time.Time `json:"expiresAt"`
	DaysLeft   int       `json:"daysLeft"`
	// StillFailing is true when the rule is failing in the target's latest scan. That
	// is the one that prevents an outage: a waiver about to expire over a finding that
	// is still failing is a gate that is about to go red.
	StillFailing bool `json:"stillFailing"`
	Expired      bool `json:"expired"`
}

// Expiring lists waivers in the target's latest scan that lapse within `within` of now,
// plus any already lapsed, soonest first, still-failing ones ahead of the rest.
func Expiring(latest model.ScanRun, now time.Time, within time.Duration) []ExpiringWaiver {
	failing := map[string]bool{}
	for _, f := range latest.Findings {
		failing[f.RuleID] = true
	}
	var out []ExpiringWaiver
	for _, w := range latest.Waivers {
		left := w.ExpiresAt.Sub(startOfDay(now))
		if left > within {
			continue
		}
		out = append(out, ExpiringWaiver{
			Target: latest.Target, Rule: w.Rule, Reason: w.Reason, ApprovedBy: w.ApprovedBy,
			ExpiresAt: w.ExpiresAt, DaysLeft: int(left / day),
			StillFailing: failing[w.Rule], Expired: left < 0,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StillFailing != out[j].StillFailing {
			return out[i].StillFailing
		}
		return out[i].ExpiresAt.Before(out[j].ExpiresAt)
	})
	return out
}

// RuleFailures counts, per rule, the targets on which it fails in their latest scan.
type RuleFailures struct {
	RuleID  string `json:"ruleId"`
	Targets int    `json:"targets"`
}

// MostFailing ranks rules by how many targets currently fail them.
func MostFailing(latest []model.ScanRun) []RuleFailures {
	count := map[string]int{}
	for _, s := range latest {
		seen := map[string]bool{}
		for _, f := range s.Findings {
			if !seen[f.RuleID] {
				seen[f.RuleID] = true
				count[f.RuleID]++
			}
		}
	}
	out := make([]RuleFailures, 0, len(count))
	for rule, n := range count {
		out = append(out, RuleFailures{RuleID: rule, Targets: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Targets != out[j].Targets {
			return out[i].Targets > out[j].Targets
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// Summary is the fleet at a glance.
type Summary struct {
	Targets       int `json:"targets"`
	Passing       int `json:"passing"`
	Failing       int `json:"failing"`
	Ungated       int `json:"ungated"`
	Stale         int `json:"stale"`
	TotalFailing  int `json:"totalFailing"`
	TotalAccepted int `json:"totalAccepted"`
}

// Summarize counts targets by the verdict of their latest scan. A target not scanned
// within `staleAfter` is counted stale and not passing: an old green is not a current
// one.
func Summarize(latest []model.ScanRun, now time.Time, staleAfter time.Duration) Summary {
	s := Summary{Targets: len(latest)}
	for _, run := range latest {
		s.TotalFailing += run.Failing
		s.TotalAccepted += run.Accepted
		switch {
		case now.Sub(run.ScannedAt) > staleAfter:
			s.Stale++
		case run.Gate == "":
			s.Ungated++
		case run.GateFailed:
			s.Failing++
		default:
			s.Passing++
		}
	}
	return s
}

func byTime(scans []model.ScanRun) []model.ScanRun {
	out := append([]model.ScanRun(nil), scans...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ScannedAt.Before(out[j].ScannedAt) })
	return out
}

func failingSet(s model.ScanRun) map[string]bool {
	set := make(map[string]bool, len(s.Findings))
	for _, f := range s.Findings {
		set[f.Fingerprint] = true
	}
	return set
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
