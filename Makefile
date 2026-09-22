SHELL := /bin/bash
PYTHON := $(shell command -v python3)
REPOSITORY_ROOT := $(shell /usr/bin/dirname "$$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)")
export PATH := /usr/bin:$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
CARGO_TARGET_DIR ?= $(REPOSITORY_ROOT)/target
export CARGO_TARGET_DIR

.PHONY: ci check test test-postgres launcher coverage dependencies licenses test-consumers
ci: check test coverage dependencies licenses test-consumers

check:
	cargo fmt --all -- --check
	cargo check --locked --workspace --all-targets --all-features
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --locked --workspace --exclude audit-postgres-integration --all-features
	$(MAKE) test-postgres

launcher:
	cargo build --locked -p audit-postgres-integration --bin audit-test-launcher

test-postgres: launcher
	RSS_TEST_RUN_ID="audit-t2-$$(date +%s)-$$$$" $(CARGO_TARGET_DIR)/debug/audit-test-launcher -- cargo test --locked -p audit-postgres-integration --test suite

coverage: launcher
	cargo llvm-cov clean --workspace
	cargo llvm-cov --locked --workspace --exclude audit-postgres-integration --all-features --no-report
	RSS_TEST_RUN_ID="audit-cov-$$(date +%s)-$$$$" $(CARGO_TARGET_DIR)/debug/audit-test-launcher -- cargo llvm-cov --locked -p audit-postgres-integration --test suite --no-report
	cargo llvm-cov report --locked --fail-under-lines 80

dependencies:
	$(PYTHON) -m unittest discover -s hack/tests -p 'test_*.py'
	$(PYTHON) hack/check_dependencies.py

licenses:
	cargo deny --locked check advisories licenses sources

test-consumers:
	$(PYTHON) hack/check_consumer.py $(if $(AUDIT_CONSUMER_REVISION),--revision "$(AUDIT_CONSUMER_REVISION)") $(if $(AUDIT_CONSUMER_OUTPUT),--output "$(AUDIT_CONSUMER_OUTPUT)")
