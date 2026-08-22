package store

import "testing"

func TestEveryMigrationHasBothDirections(t *testing.T) {
	// LoadMigrations refuses a one-way migration, so this both exercises the
	// loader and asserts the property across the real migration set.
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations were embedded")
	}
	for _, m := range migrations {
		if m.Up == "" || m.Down == "" {
			t.Errorf("migration %s is one-way", m.Version)
		}
	}
}

func TestMigrationsAreInVersionOrder(t *testing.T) {
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].Version >= migrations[i].Version {
			t.Fatalf("migrations are out of order: %s before %s",
				migrations[i-1].Version, migrations[i].Version)
		}
	}
}

func TestSplitMigrationName(t *testing.T) {
	cases := []struct {
		in        string
		version   string
		direction string
		ok        bool
	}{
		{"0001_init.up.sql", "0001", "up", true},
		{"0002_warehouse_seed.down.sql", "0002", "down", true},
		{"README.md", "", "", false},
		{"nounderscore.up.sql", "", "", false},
	}
	for _, c := range cases {
		v, d, ok := splitMigrationName(c.in)
		if ok != c.ok || v != c.version || d != c.direction {
			t.Errorf("splitMigrationName(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, v, d, ok, c.version, c.direction, c.ok)
		}
	}
}
