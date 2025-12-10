#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import re
import sys

VERSION_PATTERN = re.compile(r'(?m)^version\s*=\s*"(.*?)"')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="pyproject.toml の version フィールドを書き換えます。"
    )
    parser.add_argument(
        "--pyproject", default="pyproject.toml", help="更新対象の pyproject.toml"
    )
    parser.add_argument("--version", required=True, help="設定するバージョン")
    return parser.parse_args()


def update_version(path: pathlib.Path, version: str) -> None:
    if not path.exists():
        print(f"{path} が見つかりません。", file=sys.stderr)
        raise SystemExit(1)

    text = path.read_text(encoding="utf-8")
    new_text, count = VERSION_PATTERN.subn(f'version = "{version}"', text, count=1)
    if count != 1:
        print(
            f"{path} 内の version フィールドを特定できませんでした。", file=sys.stderr
        )
        raise SystemExit(1)
    path.write_text(new_text, encoding="utf-8")


def main() -> None:
    args = parse_args()
    update_version(pathlib.Path(args.pyproject), args.version)
    print(f"pyproject.toml を {args.version} に更新しました。")


if __name__ == "__main__":
    main()
