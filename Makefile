SHELL := /bin/bash
PYTHON := $(shell command -v python3)
REPOSITORY_ROOT := $(shell /usr/bin/dirname "$$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)")
export PATH := /usr/bin:$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
CARGO_TARGET_DIR ?= $(REPOSITORY_ROOT)/target
export CARGO_TARGET_DIR

.PHONY: ci check test dependencies licenses test-consumers
ci: check test dependencies licenses test-consumers

check:
	cargo fmt --all -- --check
	cargo check --locked --workspace --all-targets --all-features
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --locked --workspace --all-features

dependencies:
	$(PYTHON) hack/check_dependencies.py

licenses:
	cargo deny --locked check advisories licenses sources

test-consumers:
	$(PYTHON) hack/check_consumer.py $(if $(AUDIT_CONSUMER_REVISION),--revision "$(AUDIT_CONSUMER_REVISION)") $(if $(AUDIT_CONSUMER_OUTPUT),--output "$(AUDIT_CONSUMER_OUTPUT)")
