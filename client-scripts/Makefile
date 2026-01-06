.PHONY: install-prerequisites
install-prerequisites:  ## Install dependencies
	python3 -m pip install --upgrade pip
	rm -rf chakra
	git clone https://github.com/mlcommons/chakra.git
	cp utils/pyproject.toml chakra
	cd chakra && pip install .
	rm -rf chakra


.PHONY: test
test:
	pytest tests/test-unit -s -vvvv