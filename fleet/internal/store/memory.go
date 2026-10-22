package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/model"
)

// Memory is a Store held in process memory. Everything is lost on restart, which is
// why the server says so out loud when it is the one in use.
type Memory struct {
	mu     sync.Mutex
	nextID int64
	runs   []model.ScanRun
}

func NewMemory() *Memory { return &Memory{nextID: 1} }

func (m *Memory) SaveScan(_ context.Context, run model.ScanRun) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.runs {
		if existing.Target == run.Target && existing.ScannedAt.Equal(run.ScannedAt) {
			return existing.ID, nil
		}
	}
	run.ID = m.nextID
	m.nextID++
	m.runs = append(m.runs, clone(run))
	return run.ID, nil
}

func (m *Memory) LatestPerTarget(_ context.Context) ([]model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latest := map[string]model.ScanRun{}
	for _, r := range m.runs {
		if cur, ok := latest[r.Target]; !ok || r.ScannedAt.After(cur.ScannedAt) {
			latest[r.Target] = r
		}
	}
	out := make([]model.ScanRun, 0, len(latest))
	for _, r := range latest {
		out = append(out, clone(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}

func (m *Memory) Scans(_ context.Context, target string, since time.Time) ([]model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.ScanRun
	for _, r := range m.runs {
		if r.Target == target && !r.ScannedAt.Before(since) {
			out = append(out, clone(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScannedAt.Before(out[j].ScannedAt) })
	return out, nil
}

func (m *Memory) Close() {}

func clone(r model.ScanRun) model.ScanRun {
	r.Findings = append([]model.Finding(nil), r.Findings...)
	r.Waivers = append([]model.Waiver(nil), r.Waivers...)
	return r
}
