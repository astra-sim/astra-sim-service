help:
	@awk -F ':|##' '/^[^\t].+:.*##/ { printf "\033[36mmake %-28s\033[0m -%s\n", $$1, $$NF }' $(MAKEFILE_LIST) | sort

.PHONY: install-prerequisites
install-prerequisites:
	pip uninstall -y infragraph
	pip uninstall -y astra-sim-sdk
	cd client-scripts && make install-prerequisites
	cd service && make install-prerequisites
	pip install -r requirements.txt
	wget https://github.com/Keysight/infragraph/releases/download/v0.5.0/infragraph-0.5.0-py3-none-any.whl
	pip install infragraph-0.5.0-py3-none-any.whl
	rm -f infragraph-0.5.0-py3-none-any.whl

.PHONY: version
version:
	echo "Generating Version"
	rm -rf .VERSION
	grep version models/schema/api/api.yaml | cut -d: -f2 | sed -e 's/ //g' | tr -d '\n' > .VERSION
	echo "Version generated in .VERSION file"

.PHONY: build-models
build-models:
	cd models && make build

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
build-service-docker:
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
