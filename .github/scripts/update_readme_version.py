#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Update version badges in README.md")
    parser.add_argument(
        "--readme",
        type=Path,
        required=True,
        help="Path to README.md",
    )
    parser.add_argument(
        "--version",
        type=str,
        required=True,
        help="New version string (e.g. 1.0.0)",
    )
    args = parser.parse_args()

    if not args.readme.exists():
        print(f"Error: {args.readme} does not exist.")
        sys.exit(1)

    content = args.readme.read_text(encoding="utf-8")
    version = args.version
    version = version.removeprefix("v")

    # Update Release Link
    content = re.sub(
        r'href="https://github\.com/Seika139/scribe/releases/tag/v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?"',
        f'href="https://github.com/Seika139/scribe/releases/tag/v{version}"',
        content,
    )

    # Update Badge Image
    content = re.sub(
        r'src="https://img\.shields\.io/badge/version-v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?-white\.svg"',
        f'src="https://img.shields.io/badge/version-v{version}-white.svg"',
        content,
    )

    args.readme.write_text(content, encoding="utf-8")
    print(f"Updated {args.readme} version to v{version}")


if __name__ == "__main__":
    main()
