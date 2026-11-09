.PHONY: help install sync scan audit lint check format clean

TARGET ?= .
STRICT ?= 0
FLAGS ?=

ifeq ($(STRICT), 1)
	STRICT_FLAG := --strict
else
	STRICT_FLAG :=
endif

help: ## Show this help message
	@echo "repo-auditor Makefile commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Usage examples:"
	@echo "  make scan                         # Scan current directory"
	@echo "  make scan TARGET=/path/to/repo   # Scan specified directory or GitHub URL"
	@echo "  make scan TARGET=. STRICT=1      # Scan with strict exit code on warnings"
	@echo "  make lint                         # Check code with Ruff"
	@echo "  make format                       # Auto-format code with Ruff"

install: sync ## Install dependencies into virtualenv

sync: ## Sync dependencies with uv
	uv sync

scan: ## Run security scan on TARGET (default: .)
	uv run repo-auditor $(TARGET) $(STRICT_FLAG) $(FLAGS)

audit: scan ## Alias for scan

lint: ## Run Ruff linter
	uv run ruff check

check: lint ## Alias for lint

format: ## Format code with Ruff
	uv run ruff format
	uv run ruff check --fix

clean: ## Remove virtualenv and temporary build artifacts
	rm -rf .venv dist build .ruff_cache
