// Package store persists scans.
//
// Two implementations satisfy one interface and one contract suite: an in-memory
// store for development and tests, and Postgres for anything that must survive a
// restart. The contract suite in storetest runs against both, so "the memory store
// passes" and "Postgres passes" are the same claim.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/model"
)

// ErrNotFound is returned when a target has no scans.
var ErrNotFound = errors.New("not found")

// Store is everything the service needs from storage.
type Store interface {
	// SaveScan records a scan and returns its id. Saving the same scan twice -- the
	// same target and the same start time -- records it once and returns the original
	// id: a retried publish must not double-count a day.
	SaveScan(ctx context.Context, run model.ScanRun) (id int64, err error)

	// LatestPerTarget is the most recent scan of every target, ordered by target.
	LatestPerTarget(ctx context.Context) ([]model.ScanRun, error)

	// Scans are one target's scans at or after `since`, oldest first, with findings
	// and waivers.
	Scans(ctx context.Context, target string, since time.Time) ([]model.ScanRun, error)

	Close()
}
