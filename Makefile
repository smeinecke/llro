.PHONY: all format reformat check fix-ruff fix vulture complexity xenon bandit typecheck pyright test test-cov test-integration integration-test validate clean build publish-testpypi publish-pypi mutation

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

test:
	uv run pytest -m "not integration"

test-cov:
	uv run pytest -m "not integration" --cov=llro --cov-report=xml --cov-report=term-missing

# Docker-based integration tests (builds the compose testbed; needs a docker daemon)
# --no-cov: the daemon runs inside the container, so no local coverage is collected.
test-integration:
	uv run pytest tests/test_integration_compose.py -v -m integration --timeout=300 --no-cov

integration-test: test-integration

vulture:
	uv run vulture . --exclude .venv,dist,build,mutants

complexity:
	uv run radon cc src -a -nc

xenon:
	uv run xenon -b D -m B -a B src

bandit:
	uv run bandit -c pyproject.toml -r src

typecheck:
	PYRIGHT_PYTHON_FORCE_VERSION=latest uv run pyright

pyright: typecheck

# Mutation testing (mutmut). Runs the non-integration suite per mutant.
mutation:
	uv run mutmut run && uv run mutmut results

validate: format check typecheck vulture complexity xenon bandit
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
