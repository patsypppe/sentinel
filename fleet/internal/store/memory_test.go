package store_test

import (
	"testing"

	"github.com/patsypppe/sentinel/fleet/internal/store"
	"github.com/patsypppe/sentinel/fleet/internal/store/storetest"
)

func TestMemoryStoreSatisfiesTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() })
}
