# For Developers

## Dependencies

- `Python`: 3.10 or higher
- `poetry`: This project uses Poetry for dependency management.

## Development Setup

```bash
# After cloning the repository
poetry install --group dev
```

## Tests

```bash
poetry run pytest tests
```

## Coding Style

use `black` for formatting and `isort` for import sorting.
use `flake8` for linting and `mypy` for type checking.

```bash
# formatting
poetry run isort scribe tests && poetry run black scribe tests

# linting
poetry run flake8 scribe tests

# type checking
poetry run mypy scribe tests
```

## CI

CI which is configured in `.github/workflows/ci.yml` will be triggered on push or pull request to the main branch.

## Git Commit Guidelines

Not yet defined.
