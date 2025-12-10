# For Developers

## Dependencies

- `Python`: >=3.10, <=3.13
- `uv`: This project uses uv for dependency management.

## Recommended Packages

- `mise`: Run `mise` commands to simplify the development process.
- `Docker`: Tests can be run in a Docker container.

## Development Setup

```bash
# After cloning the repository
mise init
```

## Coding Style

```bash
# format code with ruff
mise format


# ruff check & mypy type check & pytest
mise check
```

## CI

CI which is configured in [.github/workflows/qualify.yml](https://github.com/Seika139/scribe/actions/workflows/qualify.yml) will be triggered on push or pull request to the main branch.

## Git Commit Guidelines

Not yet defined.
