#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CHANGELOG.md の Unreleased セクション"
        "直後に新しいリリース見出しを挿入します。"
    )
    parser.add_argument(
        "--changelog", default="CHANGELOG.md", help="更新する CHANGELOG.md"
    )
    parser.add_argument(
        "--version", required=True, help="リリースバージョン (例: 0.2.0)"
    )
    parser.add_argument("--date", required=True, help="リリース日 (YYYY-MM-DD)")
    parser.add_argument(
        "--marker", default="## [Unreleased]", help="挿入位置となるマーカー文字列"
    )
    return parser.parse_args()


def insert_release_heading(
    path: pathlib.Path, version: str, date: str, marker: str
) -> None:
    if not path.exists():
        print(f"{path} が見つかりません。", file=sys.stderr)
        raise SystemExit(1)

    text = path.read_text(encoding="utf-8")
    heading = f"## [{version}] - {date}"

    if heading in text:
        print(f"{heading} は既に存在します。", file=sys.stderr)
        raise SystemExit(1)

    try:
        idx = text.index(marker) + len(marker)
    except ValueError:
        print(f"{path} に '{marker}' セクションが見つかりません。", file=sys.stderr)
        raise SystemExit(1) from ValueError

    insertion = f"\n\n{heading}\n\n"
    updated = _normalize_blank_lines(text[:idx] + insertion + text[idx:])
    path.write_text(updated, encoding="utf-8")


def _normalize_blank_lines(text: str) -> str:
    """2 行以上の空行を 1 行にまとめる。

    Returns:
        str: 空行が正規化された文字列。
    """
    lines: list[str] = []
    blank = False
    for line in text.splitlines(keepends=True):
        if not line.strip():
            if not blank:
                lines.append(line)
            blank = True
        else:
            lines.append(line)
            blank = False
    return "".join(lines)


def main() -> None:
    args = parse_args()
    insert_release_heading(
        pathlib.Path(args.changelog), args.version, args.date, args.marker
    )
    print(f"CHANGELOG に {args.version} ({args.date}) を追加しました。")


if __name__ == "__main__":
    main()
