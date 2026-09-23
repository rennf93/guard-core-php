#!/usr/bin/env python3
"""
Version bump helper script for guard-core-php.

PHP packages carry no version file: the version is derived by Packagist
from the git tag (vX.Y.Z). The only thing this script updates is the
CHANGELOG.md scaffold for the new version, which the release engineer
fills in with the real entry content before tagging.

Usage:
    python .github/scripts/bump_version.py <version>
    make bump-version VERSION=x.y.z

No external dependencies required (stdlib only).
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve project root relative to this script's location
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def _insert_changelog_scaffold(path: Path, version: str, label: str) -> bool:
    """Insert a version scaffold block into the changelog file."""
    content = path.read_text()
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    header = f"v{version} ({today})"

    # Check if this version already has an entry
    if f"v{version} (" in content:
        print(f"  {label}: v{version} entry already exists")
        return True

    scaffold = (
        f"{header}\n"
        f"-------------------\n"
        f"\n"
        f"TITLE (v{version})\n"
        f"------------\n"
        f"\n"
        f"CONTENT\n"
        f"\n"
        f"___\n"
        f"\n"
    )

    # Find the first existing version entry to insert before it
    version_header_pattern = re.compile(r"^v\d+\.\d+\.\d+ \(", re.MULTILINE)
    match = version_header_pattern.search(content)
    if match:
        insert_pos = match.start()
        new_content = content[:insert_pos] + scaffold + content[insert_pos:]
    else:
        # No existing entries, append at end
        new_content = content.rstrip() + "\n\n" + scaffold

    path.write_text(new_content)
    print(f"  {label}: added v{version} scaffold")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <version>")
        print("  version must be in X.Y.Z format")
        return 1

    version = sys.argv[1]

    if not VERSION_PATTERN.match(version):
        print(f"Error: '{version}' is not a valid version. Expected format: X.Y.Z")
        return 1

    print(f"Bumping version to {version}...\n")
    print("Note: guard-core-php has no version file; the git tag (vX.Y.Z) is the")
    print("version Packagist publishes. Only CHANGELOG.md is scaffolded.\n")

    changelog = PROJECT_ROOT / "CHANGELOG.md"
    if not changelog.exists():
        print(f"  ERROR: Could not find {changelog}")
        return 1

    ok = _insert_changelog_scaffold(changelog, version, "CHANGELOG.md")

    print()
    print("Version bump complete." if ok else "Version bump completed with errors.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
