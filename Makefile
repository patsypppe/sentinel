# Sentinel — two products, one repository.
#   broker/   a Go MCP server built natively on MCP 2026-07-28
#   harness/  `sentinel`, a conformance harness that grades any MCP server
#
# Go 1.23+ is required. Homebrew's Go is preferred when present because the
# system Go on some machines is older than the module's floor.
GO := $(shell command -v /opt/homebrew/bin/go 2>/dev/null || command -v go)
UV := uv

BROKER_PKGS := ./broker/...

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- verify ----

.PHONY: check
check: lint test-go lint-py typecheck test-py ## Everything that must be green before a commit

.PHONY: lint
lint: ## golangci-lint over the broker
	golangci-lint run $(BROKER_PKGS)

.PHONY: test-go
test-go: ## Go unit tests
	$(GO) test $(BROKER_PKGS)

.PHONY: test-go-integration
test-go-integration: ## Go tests that need Postgres (build tag: integration)
	$(GO) test -tags=integration -count=1 $(BROKER_PKGS)

.PHONY: lint-py
lint-py: ## ruff
	$(UV) run ruff check .

.PHONY: fmt
fmt: ## Format both languages in place
	$(GO) fmt $(BROKER_PKGS)
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

.PHONY: typecheck
typecheck: ## mypy --strict over the harness
	$(UV) run mypy

.PHONY: test-py
test-py: ## Harness unit tests
	$(UV) run pytest tests -m unit -q

.PHONY: test-e2e
test-e2e: ## End-to-end suite (requires `make up`)
	$(UV) run pytest tests/e2e -m e2e -q

.PHONY: test
test: test-go test-py ## All unit tests, both languages

# --------------------------------------------------------------- compose ----

.PHONY: up
up: ## Bring up postgres, broker, envoy, smokescreen, otel-collector
	docker compose up -d --build

.PHONY: down
down: ## Tear the stack down, volumes included
	docker compose down -v

.PHONY: logs
logs: ## Follow broker logs
	docker compose logs -f broker

# ------------------------------------------------------------ deliverables ---

.PHONY: measure
measure: ## Regenerate MEASUREMENTS.md
	$(UV) run python scripts/measure.py

.PHONY: demo
demo: ## Run the nine-step demo from docs/HANDOFF.md §13
	$(UV) run python scripts/demo.py

.PHONY: scan-broker
scan-broker: ## Scan the running broker; exits 0 when it passes the MUST gate
	$(UV) run sentinel scan --endpoint http://localhost:8080/mcp --gate must --format text

.PHONY: scan-fixture
scan-fixture: ## Scan the non-conformant fixture; expected to exit 1
	$(UV) run sentinel scan --endpoint http://localhost:9000/mcp --gate must --format text
