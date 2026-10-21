// Package dashboard renders the fleet service's HTML.
//
// Server-rendered, no JavaScript, no bundler, no external request of any kind, a
// strict CSP on every response. The dashboard is a read of the same data the API
// serves, not a second implementation of it. Charts are inline SVG built from
// integers, which is both why they need no script and why a hostile string in a stored
// report cannot reach them.
package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/posture"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/app.css
var css []byte

// Row is one target in the fleet grid.
type Row struct {
	Key           string
	Name          string
	Endpoint      string
	Status        string
	Gate          string
	Failing       int
	Accepted      int
	Indeterminate int
	LastScan      time.Time
	Age           string
}

// FleetPage is the front page.
type FleetPage struct {
	Summary     posture.Summary
	Rows        []Row
	MostFailing []posture.RuleFailures
	Generated   time.Time
}

// TargetPage is one target's posture over time.
type TargetPage struct {
	Key         string
	Name        string
	Status      string
	Window      string
	Daily       []posture.DayPoint
	Chart       template.HTML
	Open        []posture.OpenFinding
	Remediation []posture.RuleRemediation
	Drift       []posture.DriftEvent
}

// WaiversPage lists the waivers that are about to lapse, or already have.
type WaiversPage struct {
	Within  string
	Waivers []posture.ExpiringWaiver
}

// Renderer holds the parsed templates.
type Renderer struct{ tpl *template.Template }

// New parses the embedded templates.
func New() (*Renderer, error) {
	funcs := template.FuncMap{
		"short": func(s string) string {
			if len(s) > 12 {
				return s[:12]
			}
			return s
		},
		"date":    func(t time.Time) string { return t.UTC().Format("2006-01-02") },
		"stamp":   func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"lastseg": func(s string) string { return s[strings.LastIndex(s, "/")+1:] },
		"pct":     pct,
		// dict builds the small map a page passes to the shared header.
		"dict": func(kv ...string) map[string]string {
			m := make(map[string]string, len(kv)/2)
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i]] = kv[i+1]
			}
			return m
		},
	}
	tpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("dashboard templates: %w", err)
	}
	return &Renderer{tpl: tpl}, nil
}

func pct(n, total int) int {
	if total == 0 {
		return 0
	}
	return n * 100 / total
}

func (r *Renderer) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := r.tpl.ExecuteTemplate(w, name, data); err != nil {
		// Headers are gone by now; the only honest thing is to stop.
		_, _ = io.WriteString(w, "\n<!-- render failed -->")
	}
}

// Fleet writes the front page.
func (r *Renderer) Fleet(w http.ResponseWriter, p FleetPage) { r.render(w, "fleet.html", p) }

// Target writes a target's page.
func (r *Renderer) Target(w http.ResponseWriter, p TargetPage) { r.render(w, "target.html", p) }

// Waivers writes the expiring-waivers page.
func (r *Renderer) Waivers(w http.ResponseWriter, p WaiversPage) { r.render(w, "waivers.html", p) }

// StaticHandler serves the one stylesheet.
func StaticHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(css)
	}
}

// Chart draws the failing count per scanned day as an inline SVG. Days with no scan are
// gaps, not zeros, so a line segment is only drawn between days that were both scanned.
// Every number in it is an integer produced here, never a string from a report.
func Chart(points []posture.DayPoint) template.HTML {
	const width, height, pad = 640, 140, 18
	if len(points) == 0 {
		return template.HTML(`<p class="muted">No scans in this window.</p>`)
	}
	peak := 1
	for _, p := range points {
		if p.Failing+p.Accepted > peak {
			peak = p.Failing + p.Accepted
		}
	}
	x := func(i int) int {
		if len(points) == 1 {
			return width / 2
		}
		return pad + i*(width-2*pad)/(len(points)-1)
	}
	y := func(v int) int { return height - pad - v*(height-2*pad)/peak }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Failing findings per day">`, width, height)
	fmt.Fprintf(&b, `<line class="axis" x1="%d" y1="%d" x2="%d" y2="%d"/>`, pad, height-pad, width-pad, height-pad)
	for i, p := range points {
		if p.GateFailed {
			fmt.Fprintf(&b, `<circle class="bad" cx="%d" cy="%d" r="4"/>`, x(i), y(p.Failing))
		} else {
			fmt.Fprintf(&b, `<circle class="ok" cx="%d" cy="%d" r="4"/>`, x(i), y(p.Failing))
		}
		if i > 0 {
			fmt.Fprintf(&b, `<line class="seg" x1="%d" y1="%d" x2="%d" y2="%d"/>`,
				x(i-1), y(points[i-1].Failing), x(i), y(p.Failing))
		}
	}
	fmt.Fprintf(&b, `<text class="lbl" x="%d" y="%d">%d</text>`, pad, pad-4, peak)
	b.WriteString(`</svg>`)
	// Safe: built only from format verbs applied to ints and constant markup.
	return template.HTML(b.String()) // #nosec G203
}
