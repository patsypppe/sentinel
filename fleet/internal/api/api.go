// Package api is the fleet service's HTTP surface: ingest, reads, and the dashboard.
//
// Three decisions shape it:
//
//   - Ingest and read are separate credentials. The token that lets a CI job publish a
//     scan must not be the one that lets anyone read the fleet's weaknesses, and a
//     read-only dashboard viewer must not be able to forge a clean scan.
//   - A server with no ingest token does not start. An open ingest endpoint would let
//     anyone make any target look green.
//   - Every response carries a strict Content-Security-Policy and nothing in the
//     dashboard makes an external request, so a hostile target name or finding detail
//     in a stored report cannot become script in an operator's browser.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/dashboard"
	"github.com/patsypppe/sentinel/fleet/internal/model"
	"github.com/patsypppe/sentinel/fleet/internal/posture"
	"github.com/patsypppe/sentinel/fleet/internal/store"
)

// MaxReportBytes bounds a published report. A full v2 report is tens of kilobytes;
// eight megabytes is generous, and unbounded is a way to fill a disk.
const MaxReportBytes = 8 << 20

// history is how far back posture is computed from. Findings older than a year are
// out of scope for "how long has this been open".
const history = 365 * 24 * time.Hour

// Config configures New.
type Config struct {
	Store store.Store
	// IngestToken authorises POST /api/v1/scans. Required.
	IngestToken string
	// ReadToken, when set, is required to read the API and the dashboard, as a bearer
	// token or as the password of HTTP Basic (so a browser can prompt for it). When
	// empty, reads are open, and the caller is expected to say so loudly.
	ReadToken string
	// StaleAfter is how old a target's latest scan may be before it stops counting as
	// passing. Defaults to 48 hours.
	StaleAfter time.Duration
	Now        func() time.Time
	Logger     *slog.Logger
}

type server struct {
	cfg  Config
	view *dashboard.Renderer
}

// New builds the handler.
func New(cfg Config) (http.Handler, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: a Store is required")
	}
	if cfg.IngestToken == "" {
		return nil, errors.New("api: an ingest token is required; without one anyone could " +
			"publish a clean scan for any target")
	}
	if cfg.StaleAfter == 0 {
		cfg.StaleAfter = 48 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	view, err := dashboard.New()
	if err != nil {
		return nil, err
	}
	s := &server{cfg: cfg, view: view}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /api/v1/scans", s.ingest)
	mux.Handle("GET /api/v1/targets", s.read(s.targets))
	mux.Handle("GET /api/v1/targets/{name}/posture", s.read(s.targetPosture))
	mux.Handle("GET /api/v1/targets/{name}/drift", s.read(s.targetDrift))
	mux.Handle("GET /api/v1/waivers/expiring", s.read(s.expiring))
	mux.Handle("GET /api/v1/fleet/summary", s.read(s.summary))
	mux.Handle("GET /", s.read(s.pageFleet))
	mux.Handle("GET /targets/{name}", s.read(s.pageTarget))
	mux.Handle("GET /waivers", s.read(s.pageWaivers))
	mux.Handle("GET /static/app.css", s.read(dashboard.StaticHandler()))
	return secure(mux), nil
}

// secure applies the response headers every reply carries.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' data:; "+
				"form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- auth

func bearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if token, ok := strings.CutPrefix(header, "Bearer "); ok {
		return strings.TrimSpace(token)
	}
	if _, password, ok := r.BasicAuth(); ok {
		return password
	}
	return ""
}

func tokenOK(got, want string) bool {
	// Constant time, so a token cannot be guessed a byte at a time from response timing.
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *server) read(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.ReadToken != "" && !tokenOK(bearer(r), s.cfg.ReadToken) {
			w.Header().Add("WWW-Authenticate", `Basic realm="sentinel", charset="UTF-8"`)
			w.Header().Add("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "a read token is required")
			return
		}
		next(w, r)
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// parseDuration reads "90d", "12h", "30m". A day is 24 hours; Go's own parser has no
// day unit and an API that asks for "2160h" to mean 90 days is an API nobody uses.
func parseDuration(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > 3650 {
			return 0, errors.New("a duration in days is 1d to 3650d")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("a duration looks like 90d, 12h or 30m")
	}
	return d, nil
}

func find(latest []model.ScanRun, key string) (model.ScanRun, bool) {
	for _, r := range latest {
		if r.Target == key || (r.Name != "" && r.Name == key) {
			return r, true
		}
	}
	return model.ScanRun{}, false
}

// ---------------------------------------------------------------- ingest

func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(bearer(r), s.cfg.IngestToken) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "an ingest token is required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxReportBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "the report is larger than the limit")
			return
		}
		writeError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	run, err := model.ParseReport(body, s.cfg.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.cfg.Store.SaveScan(r.Context(), run)
	if err != nil {
		s.cfg.Logger.Error("save scan", "target", run.Target, "err", err)
		writeError(w, http.StatusInternalServerError, "the scan could not be stored")
		return
	}
	s.cfg.Logger.Info("scan ingested", "id", id, "target", run.Target,
		"failing", run.Failing, "accepted", run.Accepted)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "target": run.Target})
}

// ---------------------------------------------------------------- reads

type targetRow struct {
	Target        string    `json:"target"`
	Name          string    `json:"name,omitempty"`
	Endpoint      string    `json:"endpoint"`
	LastScan      time.Time `json:"lastScan"`
	Status        string    `json:"status"`
	Gate          string    `json:"gate,omitempty"`
	Failing       int       `json:"failing"`
	Accepted      int       `json:"accepted"`
	Indeterminate int       `json:"indeterminate"`
	ManifestHash  string    `json:"manifestHash,omitempty"`
}

// status is the verdict of a target's latest scan. Stale wins over a green: an old
// pass is not a current one.
func (s *server) status(r model.ScanRun) string {
	switch {
	case s.cfg.Now().Sub(r.ScannedAt) > s.cfg.StaleAfter:
		return "stale"
	case r.Gate == "":
		return "ungated"
	case r.GateFailed:
		return "failing"
	default:
		return "passing"
	}
}

func (s *server) latest(ctx context.Context) ([]model.ScanRun, error) {
	return s.cfg.Store.LatestPerTarget(ctx)
}

func (s *server) rows(latest []model.ScanRun) []targetRow {
	out := make([]targetRow, 0, len(latest))
	for _, r := range latest {
		out = append(out, targetRow{
			Target: r.Target, Name: r.Name, Endpoint: r.Endpoint, LastScan: r.ScannedAt,
			Status: s.status(r), Gate: r.Gate, Failing: r.Failing, Accepted: r.Accepted,
			Indeterminate: r.Indeterminate, ManifestHash: r.ManifestHash,
		})
	}
	return out
}

func (s *server) targets(w http.ResponseWriter, r *http.Request) {
	latest, err := s.latest(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "targets could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": s.rows(latest)})
}

type postureView struct {
	Target      string                    `json:"target"`
	Name        string                    `json:"name,omitempty"`
	Window      string                    `json:"window"`
	Status      string                    `json:"status"`
	Daily       []posture.DayPoint        `json:"daily"`
	Open        []posture.OpenFinding     `json:"open"`
	Remediation []posture.RuleRemediation `json:"remediation"`
	Drift       []posture.DriftEvent      `json:"drift"`
}

func (s *server) buildPosture(
	ctx context.Context, key string, window time.Duration, label string,
) (postureView, int, string) {
	latest, err := s.latest(ctx)
	if err != nil {
		return postureView{}, http.StatusInternalServerError, "targets could not be read"
	}
	row, ok := find(latest, key)
	if !ok {
		return postureView{}, http.StatusNotFound, "no such target"
	}
	now := s.cfg.Now()
	scans, err := s.cfg.Store.Scans(ctx, row.Target, now.Add(-history))
	if err != nil {
		return postureView{}, http.StatusInternalServerError, "scans could not be read"
	}
	return postureView{
		Target: row.Target, Name: row.Name, Window: label, Status: s.status(row),
		Daily:       posture.Daily(scans, window, now),
		Open:        posture.Open(scans, now),
		Remediation: posture.Remediation(scans),
		Drift:       posture.Drift(scans),
	}, 0, ""
}

func (s *server) targetPosture(w http.ResponseWriter, r *http.Request) {
	window, err := parseDuration(r.URL.Query().Get("window"), 90*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, "window: "+err.Error())
		return
	}
	label := r.URL.Query().Get("window")
	if label == "" {
		label = "90d"
	}
	view, status, msg := s.buildPosture(r.Context(), r.PathValue("name"), window, label)
	if status != 0 {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *server) targetDrift(w http.ResponseWriter, r *http.Request) {
	view, status, msg := s.buildPosture(r.Context(), r.PathValue("name"), 90*24*time.Hour, "90d")
	if status != 0 {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": view.Target, "drift": view.Drift})
}

func (s *server) expiringWaivers(
	ctx context.Context, within time.Duration,
) ([]posture.ExpiringWaiver, int, string) {
	latest, err := s.latest(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, "targets could not be read"
	}
	now := s.cfg.Now()
	var all []posture.ExpiringWaiver
	for _, run := range latest {
		all = append(all, posture.Expiring(run, now, within)...)
	}
	// Still-failing first across the fleet, then soonest.
	sortWaivers(all)
	return all, 0, ""
}

func (s *server) expiring(w http.ResponseWriter, r *http.Request) {
	within, err := parseDuration(r.URL.Query().Get("within"), 30*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, "within: "+err.Error())
		return
	}
	all, status, msg := s.expiringWaivers(r.Context(), within)
	if status != 0 {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"waivers": all})
}

func (s *server) summary(w http.ResponseWriter, r *http.Request) {
	latest, err := s.latest(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "targets could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":     posture.Summarize(latest, s.cfg.Now(), s.cfg.StaleAfter),
		"mostFailing": posture.MostFailing(latest),
	})
}
