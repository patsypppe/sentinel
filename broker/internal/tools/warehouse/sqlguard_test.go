package warehouse

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestAllowlistPermitsExactRelationsOnly(t *testing.T) {
	allow := NewAllowlist(
		Grant{Schema: "warehouse", Table: "orders"},
		Grant{Schema: "warehouse", Table: "customers"},
	)

	if !allow.Permits("warehouse", "orders") {
		t.Error("a granted relation must be permitted")
	}
	if allow.Permits("warehouse_restricted", "payroll") {
		t.Error("an ungranted relation must be refused")
	}
	if allow.Permits("warehouse", "orders_archive") {
		t.Error("a name sharing a prefix with a granted table must be refused")
	}
	if allow.Permits("public", "orders") {
		t.Error("the same table name in another schema must be refused")
	}
}

func TestEmptyAllowlistPermitsNothing(t *testing.T) {
	allow := NewAllowlist()
	if allow.Permits("warehouse", "orders") {
		t.Fatal("an empty allowlist must permit nothing: that is the correct default for a " +
			"principal holding no warehouse scopes")
	}
}

func TestAllowlistForUnknownScopeGrantsNothing(t *testing.T) {
	allow := AllowlistFor([]string{"warehouse:reader", "warehouse", "WAREHOUSE:READ"})
	if len(allow.Relations()) != 0 {
		t.Fatalf("near-miss scope names granted %v; scope matching is exact, with no "+
			"prefix or case rule", allow.Relations())
	}
}

func TestAllowlistForRealScopeGrantsRelations(t *testing.T) {
	allow := AllowlistFor([]string{"warehouse:read"})
	if !allow.Permits("warehouse", "orders") {
		t.Fatal("warehouse:read must grant warehouse.orders")
	}
	if allow.Permits("warehouse_restricted", "payroll") {
		t.Fatal("warehouse:read must not grant the restricted schema")
	}
}

func TestRelationsAreSortedForStableErrors(t *testing.T) {
	allow := NewAllowlist(
		Grant{Schema: "warehouse", Table: "orders"},
		Grant{Schema: "warehouse", Table: "customers"},
	)
	rel := allow.Relations()
	if len(rel) != 2 || rel[0] != "warehouse.customers" || rel[1] != "warehouse.orders" {
		t.Fatalf("relations = %v, want them sorted so error messages are stable", rel)
	}
}

func TestCheckAllowlistNamesTheOffendingRelation(t *testing.T) {
	allow := AllowlistFor([]string{"warehouse:read"})

	err := CheckAllowlist([]string{"warehouse.orders", "warehouse_restricted.payroll"}, allow)
	if err == nil {
		t.Fatal("a plan touching a denied relation must be refused")
	}
	var denied *ErrRelationDenied
	if !errors.As(err, &denied) {
		t.Fatalf("err = %T, want *ErrRelationDenied", err)
	}
	if denied.Relation != "warehouse_restricted.payroll" {
		t.Fatalf("error names %q, want the denied relation", denied.Relation)
	}
	if !contains(denied.Error(), "warehouse.orders") {
		t.Fatalf("error %q must list what IS readable; a refusal that does not say what "+
			"would have worked forces the caller to guess", denied.Error())
	}
}

func TestCheckAllowlistPassesWhenEverythingIsPermitted(t *testing.T) {
	allow := AllowlistFor([]string{"warehouse:read"})
	if err := CheckAllowlist([]string{"warehouse.orders", "warehouse.customers"}, allow); err != nil {
		t.Fatalf("a fully permitted plan was refused: %v", err)
	}
}

// TestUnschemaedRelationIsRefused. A plan node with no schema means the
// relation resolved through search_path. The guard sets an empty search_path so
// this cannot happen, but if it ever does, the relation must be refused rather
// than have a schema assumed on the query's behalf.
func TestUnschemaedRelationIsRefused(t *testing.T) {
	var node planNode
	if err := json.Unmarshal([]byte(`{"Relation Name":"orders"}`), &node); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	node.Relations(found)

	if !found["?.orders"] {
		t.Fatalf("a schemaless relation must be recorded as unknown, got %v", found)
	}
	if err := CheckAllowlist([]string{"?.orders"}, AllowlistFor([]string{"warehouse:read"})); err == nil {
		t.Fatal("a relation whose schema could not be determined must be refused")
	}
}

// TestPlanWalkFindsNestedRelations. Subqueries, joins and CTEs all appear as
// child plan nodes, and every one of them must be checked. This is precisely
// what string inspection of the SQL cannot see.
func TestPlanWalkFindsNestedRelations(t *testing.T) {
	raw := `{
      "Relation Name": "",
      "Plans": [
        {"Relation Name": "orders", "Schema": "warehouse"},
        {"Relation Name": "", "Plans": [
          {"Relation Name": "payroll", "Schema": "warehouse_restricted"}
        ]}
      ]
    }`
	var node planNode
	if err := json.Unmarshal([]byte(raw), &node); err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	node.Relations(found)

	if !found["warehouse.orders"] {
		t.Error("a top-level scan was not found")
	}
	if !found["warehouse_restricted.payroll"] {
		t.Error("a relation nested two levels deep was not found; a query can hide a denied " +
			"table inside a subquery and it must still be checked")
	}
}

func TestErrNotReadOnlyExplainsWhatToDo(t *testing.T) {
	err := &ErrNotReadOnly{Detail: "cannot execute UPDATE in a read-only transaction"}
	if !contains(err.Error(), "SELECT") {
		t.Fatalf("error %q must say what would have worked", err.Error())
	}
}
