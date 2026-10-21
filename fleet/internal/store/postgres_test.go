//go:build integration

package store_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/patsypppe/sentinel/fleet/internal/store"
	"github.com/patsypppe/sentinel/fleet/internal/store/storetest"
)

func adminURL(t *testing.T) string {
	t.Helper()
	value := os.Getenv("FLEET_TEST_DATABASE_URL")
	if value == "" {
		t.Skip("FLEET_TEST_DATABASE_URL is not set")
	}
	return value
}

// scratch creates a throwaway database and returns its URL.
func scratch(t *testing.T) string {
	t.Helper()
	admin := adminURL(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("fleet_test_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		_ = conn.Close(ctx)
	})
	// pgx's ConnString() returns the string it was parsed from, not the config as
	// edited, so the database name has to be swapped in the URL itself.
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func TestPostgresStoreSatisfiesTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		dsn := scratch(t)
		if _, err := store.Migrate(context.Background(), dsn); err != nil {
			t.Fatal(err)
		}
		s, err := store.OpenPostgres(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	})
}

func TestMigrationsApplyOnceAndOnlyOnce(t *testing.T) {
	dsn := scratch(t)
	first, err := store.Migrate(context.Background(), dsn)
	if err != nil || len(first) == 0 {
		t.Fatalf("first = %v err = %v", first, err)
	}
	second, err := store.Migrate(context.Background(), dsn)
	if err != nil || len(second) != 0 {
		t.Fatalf("second = %v err = %v: a migration ran twice", second, err)
	}
}

func TestTheSchemaRefusesTwoScansOfOneTargetAtOneInstant(t *testing.T) {
	dsn := scratch(t)
	ctx := context.Background()
	if _, err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	_, _ = conn.Exec(ctx, "INSERT INTO targets VALUES ('a','','',now(),now())")
	insert := `INSERT INTO scan_runs (target, scanned_at, passing, failing, accepted, indeterminate, not_applicable)
	           VALUES ('a', '2026-10-01', 0,0,0,0,0)`
	if _, err := conn.Exec(ctx, insert); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, insert); err == nil {
		t.Fatal("a duplicate (target, scanned_at) was accepted by the schema itself")
	}
}
