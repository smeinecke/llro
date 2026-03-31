.PHONY: all format reformat check fix-ruff fix vulture xenon typecheck test integration-test validate clean build publish-testpypi publish-pypi

all: validate test

format:
	uv run ruff format --check --diff .

reformat:
	uv run ruff format .

check:
	uv run ruff check .

fix-ruff:
	uv run ruff check . --fix

fix: reformat fix-ruff
	@echo "Updated code."

vulture:
	uv run vulture . --exclude .venv,dist,build

xenon:
	uv run xenon -b D -m B -a B src

typecheck:
	uv run pyright

test:
	uv run pytest

integration-test:
	RUN_DOCKER_INTEGRATION=1 uv run --python 3.7 pytest -m integration

validate: format check typecheck vulture
	@echo "Validation passed."

clean:
	rm -rf build dist *.egg-info src/*.egg-info

build: clean
	uv build
	uv run python -m twine check dist/*

publish-testpypi: build
	uv run python -m twine upload --repository testpypi dist/*

publish-pypi: build
	uv run python -m twine upload dist/*
