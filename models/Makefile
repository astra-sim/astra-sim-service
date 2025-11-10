PACKAGE_NAME := astra_sim_sdk
CI_COMMIT_REF_NAME ?= $(shell git symbolic-ref --short HEAD)
VERSION_FROM_FILE := $(shell cat ../.VERSION)

.PHONY: clean
clean:
	rm -rf artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf astra_sim_sdk
	rm -rf .GENERATED_VERSION

.PHONY: clean-openapiart
clean-openapiart:

	rm -rf openapiart
	pip uninstall -y openapiart

# .PHONY: get-openapiart
# get-openapiart: clean-openapiart
# 	git clone --branch v0.3.37 --single-branch https://github.com/open-traffic-generator/openapiart
# 	cd openapiart/openapiart && pip install -r requirements.txt
# 	cd openapiart && python3 do.py version > openapiart_version.txt
# 	OPENAPI_VERSION=$$(cat openapiart/openapiart_version.txt); \
# 	cd openapiart && pip install .
# 	rm -rf openapiart

.PHONY: infragraph
infragraph:
	rm -rf ./schema/infragraph/infragraph.yaml
	rm -rf infragraph
	git clone --branch v0.5.0 --depth 1 https://github.com/Keysight/infragraph
	cp infragraph/models/infrastructure.yaml ./schema/infragraph/infragraph.yaml
	cp infragraph/models/device.yaml ./schema/infragraph/device.yaml
	cp infragraph/models/link.yaml ./schema/infragraph/link.yaml
	cp infragraph/models/instance.yaml ./schema/infragraph/instance.yaml
	cp infragraph/models/edge.yaml ./schema/infragraph/edge.yaml
	cp infragraph/models/common.yaml ./schema/infragraph/common.yaml
	cp infragraph/models/component.yaml ./schema/infragraph/component.yaml
	rm -rf infragraph

.PHONY: version
version: ## Generate build version
	chmod +x ../make_version.sh && \
	CI_COMMIT_REF_NAME=$(CI_COMMIT_REF_NAME) \
	export CI_COMMIT_REF_NAME; \
	VERSION_FROM_FILE=$$(cat ../.VERSION); \
	export VERSION_FROM_FILE; \
    ../make_version.sh $$VERSION_FROM_FILE > .GENERATED_VERSION

.PHONY: build
build: clean version infragraph
	VERSION=$$(cat .GENERATED_VERSION); \
	export VERSION; export PACKAGE_NAME=$(PACKAGE_NAME); python3 build.py
	cp artifacts/openapi.yaml artifacts/${PACKAGE_NAME}/openapi.yaml
	mv artifacts/${PACKAGE_NAME} ${PACKAGE_NAME}
	sed -i 's/log.addHandler(stderr_handler)/#log.addHandler(stderr_handler)/' ${PACKAGE_NAME}/${PACKAGE_NAME}.py
# make redocly
	VERSION=$$(cat .GENERATED_VERSION); \
	export VERSION; export PACKAGE_NAME=$(PACKAGE_NAME);python3 setup.py bdist_wheel
	pip install dist/*.whl

.PHONY: redocly
redocly:
	redocly build-docs ./artifacts/openapi.yaml -o ./artifacts/openapi.html
	cp ./artifacts/openapi.html ./${PACKAGE_NAME}/openapi.html
