CI_COMMIT_REF_NAME ?= $(shell git symbolic-ref --short HEAD)
ASTRA_SIM_COMMIT_HASH ?= $(shell cat .ASTRA_SIM_GIT_COMMIT_SHA)
PY_PATHS:=${PWD}/astra_server
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
PACKAGE_NAME := astra_server
ASTRA_SIM_SERVICE_IMAGE := astra_sim_service
GENERATED_VERSION := $(shell cat ../.VERSION)
export PATH:=$(PY_PATHS):$(PATH)

help:
	@awk -F ':|##' '/^[^\t].+:.*##/ { printf "\033[36mmake %-28s\033[0m -%s\n", $$1, $$NF }' $(MAKEFILE_LIST) | sort

.PHONY: clean-astrasim
clean-astrasim:
	rm -rf astra-sim

.PHONY: clean
clean:
	pip uninstall -y $(PACKAGE_NAME) || true
	pip uninstall -y dist/*.whl || true
	rm -rf *.egg-info || true
	rm -rf dist || true
	rm -rf build/

.PHONY: install-prerequisites
install-prerequisites: clean

.PHONY: clone-astra-sim
clone-astra-sim: clean clean-astrasim
	git config --global core.autocrlf input
	git clone https://github.com/astra-sim/astra-sim && \
	cd astra-sim && \
 	git checkout $(ASTRA_SIM_COMMIT_HASH) && \
	git submodule update --init --recursive

.PHONY: build-astra-sim
build-astra-sim: clean-astrasim clone-astra-sim
	chmod +x build_script/build_backend.sh && \
	./build_script/build_backend.sh

.PHONY: build-docker
build-docker: version
	cp ../models/dist/*.whl .
	cp ../requirements.txt requirements.txt
	docker build --no-cache -t  $(ASTRA_SIM_SERVICE_IMAGE):$(GENERATED_VERSION) .
	docker save $(ASTRA_SIM_SERVICE_IMAGE):$(GENERATED_VERSION) -o $(ASTRA_SIM_SERVICE_IMAGE):$(GENERATED_VERSION).tar
	rm requirements.txt
	rm *.whl

.PHONY: version
version: ## Generate build version
	chmod +x ../make_version.sh && \
	CI_COMMIT_REF_NAME=$(CI_COMMIT_REF_NAME) \
	export CI_COMMIT_REF_NAME; \
	VERSION_FROM_FILE=$$(cat ../.VERSION); \
	export VERSION_FROM_FILE; \
    ../make_version.sh "$(GENERATED_VERSION)" > .GENERATED_VERSION

.PHONY: pre-test
pre-test:
	rm -rf tests/test-notebook
	python3 convert_nb_to_script.py

.PHONY: build
build: clean version
	black astra_server
	black tests
	python3 assign_version.py
	export PIP_EXTRA_INDEX_URL; python3 -m build
	pip install dist/*.whl
	make pre-test
	make test

.PHONY: test
test:
	pip uninstall -y $(PACKAGE_NAME) || true
	pip uninstall -y dist/*.whl || true
	pip install dist/*.whl
	export PYTHONPATH="$${PYTHONPATH}:./${PY_PATHS}"; pytest --cov=astra_server/  tests -s -vvvv