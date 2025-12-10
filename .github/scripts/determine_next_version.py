#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import re
import sys

VERSION_PATTERN = re.compile(r'(?m)^version\s*=\s*"([^"]+)"')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="pyproject.toml の現在バージョンを読み込み、"
        "次バージョンを計算します。"
    )
    parser.add_argument(
        "--pyproject",
        default="pyproject.toml",
        help="バージョンを読み取る pyproject.toml のパス",
    )
    parser.add_argument(
        "--bump",
        choices=("major", "minor", "patch"),
        required=True,
        help="バージョンアップ種別",
    )
    parser.add_argument(
        "--env-file",
        required=True,
        help="結果を書き込む環境ファイル(GITHUB_ENV)",
    )
    return parser.parse_args()


def read_current_version(path: pathlib.Path) -> str:
    if not path.exists():
        print(f"{path} が見つかりません。", file=sys.stderr)
        raise SystemExit(1)
    match = VERSION_PATTERN.search(path.read_text(encoding="utf-8"))
    if not match:
        print(
            f"{path} 内の version フィールドを特定できませんでした。", file=sys.stderr
        )
        raise SystemExit(1)
    return match.group(1)


def bump_version(current: str, bump: str) -> str:
    parts = current.split(".")
    if len(parts) < 3:
        print(
            f"現在のバージョン {current} が SemVer 形式ではありません。",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        major, minor, patch = map(int, parts[:3])
    except ValueError:
        print(f"現在のバージョン {current} が数値形式ではありません。", file=sys.stderr)
        raise SystemExit(1) from ValueError

    if bump == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump == "minor":
        minor += 1
        patch = 0
    else:
        patch += 1

    return f"{major}.{minor}.{patch}"


def write_env(env_file: pathlib.Path, values: dict[str, str]) -> None:
    with env_file.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main() -> None:
    args = parse_args()
    pyproject = pathlib.Path(args.pyproject)
    env_file = pathlib.Path(args.env_file)

    current = read_current_version(pyproject)
    next_version = bump_version(current, args.bump)

    env_values = {
        "CURRENT_VERSION": current,
        "RELEASE_VERSION": next_version,
        "RELEASE_BRANCH": f"release/v{next_version}",
        "RELEASE_TAG": f"v{next_version}",
    }
    write_env(env_file, env_values)

    print(f"Current version: {current}")
    print(f"Version bump: {args.bump}")
    print(f"Next version: {next_version}")


if __name__ == "__main__":
    main()
