lint:
	ruff check .
	python -m mypy --check-untyped-defs pywarp

test: lint
	python -m coverage run --branch --source=pywarp ./test/test.py -v

docs:
	python -m sphinx -W -b html docs docs/html

install:
	rm -rf dist
	python -m pip install build
	python -m build
	python -m pip install --upgrade "$$(echo dist/*.whl)[tests]"

.PHONY: test lint docs install

include common.mk
