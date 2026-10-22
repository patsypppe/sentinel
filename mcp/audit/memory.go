package audit

import (
	"context"
	"sync"
)

// MemorySink keeps audit records in process memory.
//
// It exists so that a server built from this kit is auditable from the first line,
// without a database: the rule is that every invocation is recorded and a failed
// write fails the invocation, and a kit whose default was "no audit sink" would make
// the rule opt-in. It is not durable and not tamper-evident -- the records die with
// the process and nothing chains them -- so it is for development, tests and the
// example. A production server needs a sink backed by storage it does not control
// the deletion of; see PoolSink.
type MemorySink struct {
	mu      sync.Mutex
	records []Record
	limit   int
}

// NewMemorySink keeps at most `limit` records, dropping the oldest. A limit of zero
// or less means 10,000: an unbounded in-memory log is a memory leak with a name.
func NewMemorySink(limit int) *MemorySink {
	if limit <= 0 {
		limit = 10_000
	}
	return &MemorySink{limit: limit}
}

// Record appends r. It never fails, so it never fails an invocation.
func (m *MemorySink) Record(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, r)
	if over := len(m.records) - m.limit; over > 0 {
		m.records = append([]Record(nil), m.records[over:]...)
	}
	return nil
}

// Records returns a copy of what has been recorded, oldest first.
func (m *MemorySink) Records() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Record(nil), m.records...)
}

// Len is the number of records currently held.
func (m *MemorySink) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}
