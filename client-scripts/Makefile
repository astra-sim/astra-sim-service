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

.PHONY: test
test:
	pytest tests/test-unit -s -vvvv