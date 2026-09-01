SHELL := /bin/bash

PACKAGE_NAME := astra_sim_service_client
CI_COMMIT_REF_NAME ?= $(shell git symbolic-ref --short HEAD)

help:
	@awk -F ':|##' '/^[^\t].+:.*##/ { printf "\033[36mmake %-28s\033[0m -%s\n", $$1, $$NF }' $(MAKEFILE_LIST) | sort

.PHONY: install-prerequisites
install-prerequisites:  ## Install dependencies
	python3 -m pip install --upgrade pip
	rm -rf chakra
	pip install -r requirements-dev.txt
	git clone https://github.com/mlcommons/chakra.git
	# --no-build-isolation makes chakra's protoc codegen run against the
	# grpcio-tools pinned in requirements-dev.txt. Under build isolation pip
	# pulls the newest grpcio-tools into the build env, which emits gencode
	# newer than our protobuf runtime and fails at import with
	# "Detected incompatible Protobuf Gencode/Runtime versions".
	# PIP_CONSTRAINT keeps chakra's own unpinned deps (protobuf, ...) in range.
	cd chakra && PIP_CONSTRAINT=$(CURDIR)/requirements-dev.txt pip install --no-build-isolation .
	rm -rf chakra

.PHONY: clean
clean:  ## Remove build artifacts
	pip uninstall -y $(PACKAGE_NAME) || true
	rm -rf build/ || true
	rm -rf dist/ || true
	rm -rf *.egg-info || true
	rm -rf .GENERATED_VERSION || true

.PHONY: version
version:  ## Generate build version from the repo-level .VERSION
	chmod +x ../make_version.sh && \
	CI_COMMIT_REF_NAME=$(CI_COMMIT_REF_NAME) \
	export CI_COMMIT_REF_NAME; \
	VERSION_FROM_FILE=$$(cat ../.VERSION); \
	export VERSION_FROM_FILE; \
	../make_version.sh $$VERSION_FROM_FILE > .GENERATED_VERSION

.PHONY: build
build: clean version  ## Build and install the client wheel
	python3 -m build --no-isolation
	# --no-deps keeps the astra-sim-sdk that models/ just built and installed in
	# place; the pinned release wheel in pyproject.toml is for external users.
	pip install --no-deps --force-reinstall dist/*.whl

.PHONY: test
test:  ## Run the client unit tests
	pytest $(PACKAGE_NAME)/tests/test-unit -s -vvvv
