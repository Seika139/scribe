#!/usr/bin/env python3

import argparse
import os
import re
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Update version badges in README.md")
    parser.add_argument("--readme", type=Path, required=True, help="Path to README.md")
    parser.add_argument(
        "--version", type=str, required=True, help="New version (e.g. v1.0.0)"
    )
    # リポジトリ名を引数で受け取れるように追加。
    # GitHub Actions からは環境変数で渡されるのでデフォルトで取得される。
    parser.add_argument(
        "--repo",
        type=str,
        default=os.getenv("GITHUB_REPOSITORY"),
        help="Full repository name (owner/repo)",
    )
    args = parser.parse_args()

    if not args.readme.exists():
        print(f"Error: {args.readme} does not exist.")
        sys.exit(1)

    if not args.repo:
        print("Error: Repository name is required (or set GITHUB_REPOSITORY env).")
        sys.exit(1)

    content = args.readme.read_text(encoding="utf-8")

    version_raw = args.version.removeprefix("v")

    # 1. Release Link の置換 (https://github.com/owner/repo/releases/tag/v...)
    # ユーザー名/リポジトリ名の部分を動的に作成
    release_pattern = rf'href="https://github\.com/{re.escape(args.repo)}/releases/tag/v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?"'
    release_replacement = (
        f'href="https://github.com/{args.repo}/releases/tag/v{version_raw}"'
    )
    content = re.sub(release_pattern, release_replacement, content)

    # 2. Badge Image の置換 (https://img.shields.io/badge/version-v...)
    badge_pattern = r'src="https://img\.shields\.io/badge/version-v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?-white\.svg"'
    badge_replacement = (
        f'src="https://img.shields.io/badge/version-v{version_raw}-white.svg"'
    )
    content = re.sub(badge_pattern, badge_replacement, content)

    args.readme.write_text(content, encoding="utf-8")
    print(f"Updated {args.readme} in {args.repo} to v{version_raw}")


if __name__ == "__main__":
    main()
