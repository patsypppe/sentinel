package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/dashboard"
	"github.com/patsypppe/sentinel/fleet/internal/posture"
)

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/(24*time.Hour)), "day")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func (s *server) pageFleet(w http.ResponseWriter, r *http.Request) {
	latest, err := s.latest(r.Context())
	if err != nil {
		http.Error(w, "targets could not be read", http.StatusInternalServerError)
		return
	}
	now := s.cfg.Now()
	rows := make([]dashboard.Row, 0, len(latest))
	for _, run := range latest {
		rows = append(rows, dashboard.Row{
			Key: run.Target, Name: run.DisplayName(), Endpoint: run.Endpoint, Status: s.status(run),
			Gate: run.Gate, Failing: run.Failing, Accepted: run.Accepted,
			Indeterminate: run.Indeterminate, LastScan: run.ScannedAt, Age: humanAge(now.Sub(run.ScannedAt)),
		})
	}
	s.view.Fleet(w, dashboard.FleetPage{
		Summary:     posture.Summarize(latest, now, s.cfg.StaleAfter),
		Rows:        rows,
		MostFailing: posture.MostFailing(latest),
		Generated:   now,
	})
}

func (s *server) pageTarget(w http.ResponseWriter, r *http.Request) {
	view, status, msg := s.buildPosture(r.Context(), r.PathValue("name"), 90*24*time.Hour, "90 days")
	if status != 0 {
		http.Error(w, msg, status)
		return
	}
	name := view.Name
	if name == "" {
		name = view.Target
	}
	s.view.Target(w, dashboard.TargetPage{
		Key: view.Target, Name: name, Status: view.Status, Window: view.Window,
		Daily: view.Daily, Chart: dashboard.Chart(view.Daily), Open: view.Open,
		Remediation: view.Remediation, Drift: view.Drift,
	})
}

func (s *server) pageWaivers(w http.ResponseWriter, r *http.Request) {
	all, status, msg := s.expiringWaivers(r.Context(), 30*24*time.Hour)
	if status != 0 {
		http.Error(w, msg, status)
		return
	}
	s.view.Waivers(w, dashboard.WaiversPage{Within: "30 days", Waivers: all})
}
