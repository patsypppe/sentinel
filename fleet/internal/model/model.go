// Package model is what the fleet service stores about a scan.
//
// It is parsed from the schema-2 JSON report `sentinel scan --format json` writes,
// and deliberately keeps only what the service computes over: counts, the failing
// and accepted findings with their fingerprints, the manifest hash, and the waivers
// in force. A scan's passing rules are not stored. They are the absence of a
// problem, and a posture history of 90 days of 70 passing rules each would bury
// the findings that matter.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the only report schema this service accepts.
const SchemaVersion = 2

// Finding is one failing rule on one target.
type Finding struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail,omitempty"`
	// Accepted is true when the failure is waived or baselined: it is still
	// failing, and still listed, but it does not gate.
	Accepted bool `json:"accepted"`
}

// Waiver is one acknowledged decision to live with a finding, with its end date.
type Waiver struct {
	Rule       string    `json:"rule"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expiresAt"`
	ApprovedBy string    `json:"approvedBy,omitempty"`
}

// ScanRun is one scan of one target.
type ScanRun struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	Name      string    `json:"name,omitempty"`
	Endpoint  string    `json:"endpoint"`
	ScannedAt time.Time `json:"scannedAt"`

	SpecRevision string `json:"specRevision"`
	ManifestHash string `json:"manifestHash,omitempty"`
	// Gate is the gate the scan was judged against ("must", "should", "ops", ...) and
	// GateFailed whether it failed. Empty Gate means the scan only reported.
	Gate       string `json:"gate,omitempty"`
	GateFailed bool   `json:"gateFailed"`

	Passing       int `json:"passing"`
	Failing       int `json:"failing"`
	Accepted      int `json:"accepted"`
	Indeterminate int `json:"indeterminate"`
	NotApplicable int `json:"notApplicable"`

	Findings []Finding `json:"findings"`
	Waivers  []Waiver  `json:"waivers"`
}

// DisplayName is what a human should call the target.
func (s ScanRun) DisplayName() string {
	if s.Name != "" {
		return s.Name
	}
	return s.Target
}

// wire mirrors the parts of the v2 report this service reads.
type wire struct {
	SchemaVersion int     `json:"schemaVersion"`
	StartedAt     float64 `json:"startedAt"`
	SpecRevision  string  `json:"specRevision"`
	Target        struct {
		Endpoint     string  `json:"endpoint"`
		Name         *string `json:"name"`
		Identity     string  `json:"identity"`
		ManifestHash *string `json:"manifestHash"`
	} `json:"target"`
	Gate *struct {
		Selected string `json:"selected"`
		Failed   bool   `json:"failed"`
	} `json:"gate"`
	Policy struct {
		Waivers []struct {
			Rule       string `json:"rule"`
			Endpoint   string `json:"endpoint"`
			Reason     string `json:"reason"`
			ExpiresAt  string `json:"expiresAt"`
			ApprovedBy string `json:"approvedBy"`
		} `json:"waivers"`
	} `json:"policy"`
	Findings []struct {
		RuleID      string `json:"ruleId"`
		Severity    string `json:"severity"`
		Outcome     string `json:"outcome"`
		Detail      string `json:"detail"`
		Fingerprint string `json:"fingerprint"`
		WaivedBy    any    `json:"waivedBy"`
		Baselined   bool   `json:"baselined"`
	} `json:"findings"`
}

// ErrBadReport marks a report the service refuses. It is the client's fault, and
// the API answers it with 400 rather than 500.
var ErrBadReport = errors.New("report rejected")

// ParseReport reads a schema-2 report. now is used only if the report carries no
// start time, so a clock is injected rather than read.
func ParseReport(raw []byte, now time.Time) (ScanRun, error) {
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return ScanRun{}, fmt.Errorf("%w: not JSON: %w", ErrBadReport, err)
	}
	if w.SchemaVersion != SchemaVersion {
		return ScanRun{}, fmt.Errorf(
			"%w: schemaVersion is %d; this service reads %d. Re-run the scan with "+
				"`sentinel scan --schema-version 2`", ErrBadReport, w.SchemaVersion, SchemaVersion)
	}
	identity := strings.TrimSpace(w.Target.Identity)
	if identity == "" {
		return ScanRun{}, fmt.Errorf("%w: target.identity is empty", ErrBadReport)
	}

	run := ScanRun{
		Target:       identity,
		Endpoint:     w.Target.Endpoint,
		SpecRevision: w.SpecRevision,
		ScannedAt:    now.UTC(),
	}
	if w.StartedAt > 0 {
		sec := int64(w.StartedAt)
		run.ScannedAt = time.Unix(sec, int64((w.StartedAt-float64(sec))*1e9)).UTC()
	}
	if w.Target.Name != nil {
		run.Name = *w.Target.Name
	}
	if w.Target.ManifestHash != nil {
		run.ManifestHash = *w.Target.ManifestHash
	}
	if w.Gate != nil {
		run.Gate, run.GateFailed = w.Gate.Selected, w.Gate.Failed
	}

	for _, f := range w.Findings {
		switch f.Outcome {
		case "pass":
			run.Passing++
		case "not_applicable":
			run.NotApplicable++
		case "indeterminate":
			run.Indeterminate++
		case "fail":
			accepted := f.WaivedBy != nil || f.Baselined
			if accepted {
				run.Accepted++
			} else {
				run.Failing++
			}
			run.Findings = append(run.Findings, Finding{
				Fingerprint: f.Fingerprint,
				RuleID:      f.RuleID,
				Severity:    f.Severity,
				Detail:      truncate(f.Detail, 400),
				Accepted:    accepted,
			})
		default:
			return ScanRun{}, fmt.Errorf("%w: finding %s has unknown outcome %q",
				ErrBadReport, f.RuleID, f.Outcome)
		}
	}

	for _, w2 := range w.Policy.Waivers {
		expires, err := time.Parse("2006-01-02", w2.ExpiresAt)
		if err != nil {
			return ScanRun{}, fmt.Errorf("%w: waiver for %s has expiresAt %q, not YYYY-MM-DD",
				ErrBadReport, w2.Rule, w2.ExpiresAt)
		}
		run.Waivers = append(run.Waivers, Waiver{
			Rule: w2.Rule, Endpoint: w2.Endpoint, Reason: w2.Reason,
			ExpiresAt: expires.UTC(), ApprovedBy: w2.ApprovedBy,
		})
	}
	return run, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
