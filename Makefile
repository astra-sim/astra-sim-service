SHELL := /bin/bash

ASTRA_SIM_SERVICE_IMAGE := astrasim/astra-sim-service
ASTRA_SIM_SERVICE_LATEST := $(ASTRA_SIM_SERVICE_IMAGE):latest
VERSION := $(shell cat .VERSION)

help:
	@awk -F ':|##' '/^[^\t].+:.*##/ { printf "\033[36mmake %-28s\033[0m -%s\n", $$1, $$NF }' $(MAKEFILE_LIST) | sort

.PHONY: install-prerequisites
install-prerequisites:
	pip uninstall -y infragraph
	pip uninstall -y astra-sim-sdk
	cd client-scripts && make install-prerequisites
	cd service && make install-prerequisites
	pip install -r requirements.txt

.PHONY: version
version:
	echo "Generating Version"
	rm -rf .VERSION
	grep version models/schema/api/api.yaml | cut -d: -f2 | sed -e 's/ //g' | tr -d '\n' > .VERSION
	echo "Version generated in .VERSION file"

.PHONY: clean
clean:
	rm -rf venv || true

.PHONY: build-models
build-models:
	cd models && make build && make redocly

.PHONY: generate-sdk-doc
generate-sdk-doc:
	cd models && make redocly

.PHONY: test-client-scripts
test-client-scripts:
	cd client-scripts && make test

.PHONY: build-service
build-service:
	cd service && make build

.PHONY: build-service-docker
build-service-docker: install-prerequisites version build-models
	cd service && make build-docker

.PHONY: build-astra-sim
build-astra-sim:
	cd service && make build-astra-sim

.PHONY: build-all
build-all: version
	make build-models
	make test-client-scripts
	make build-astra-sim
	make build-service

.PHONY: build-bare-metal
build-bare-metal: clean
	bash bare_metal_setup.sh
	python3 -m venv venv
	source venv/bin/activate && make install-prerequisites && make build-all

.PHONY: publish-service-docker
publish-service-docker:
	docker tag astra_sim_service:$(VERSION) $(ASTRA_SIM_SERVICE_IMAGE):$(VERSION)
	docker tag astra_sim_service:$(VERSION) $(ASTRA_SIM_SERVICE_LATEST)
	docker push $(ASTRA_SIM_SERVICE_IMAGE):$(VERSION)
	docker push $(ASTRA_SIM_SERVICE_LATEST)