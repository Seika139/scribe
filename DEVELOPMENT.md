# For Developers

## Dependencies

- `Python`: 3.10 or higher
- `poetry`: This project uses Poetry for dependency management.

## Recommended Packages

- `make`: Run `make` commands to simplify the development process.
- `Docker`: Tests can be run in a Docker container.

## Development Setup

```bash
# After cloning the repository
poetry install --group dev
```

## Coding Style

use `black` for formatting and `isort` for import sorting.
use `flake8` for linting and `mypy` for type checking.

```bash
# formatting
make format

# linting & type checking
make check
```

## Tests

`make test` run `pytest` in both local and Docker environments.
If you want to run `pytest` in a Docker container, you can use `make test-docker`.
If you want to run `pytest` in your local environment, you can use `make test-local`.

After finishing the tests, remove the Docker container with `make down`.
Also, you can run `make clean` to remove all Docker containers and images.

## CI

CI which is configured in [.github/workflows/ci.yml](https://github.com/Seika139/scribe/actions/workflows/ci.yml) will be triggered on push or pull request to the main branch.

## Git Commit Guidelines

Not yet defined.
