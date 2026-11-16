#!/usr/bin/env python3
"""Validate the smart-contract-audit Agent Skill.

Pure Python standard library — no third-party dependencies, no network.

Checks:
  1. skill.md exists and opens with a `---` YAML frontmatter block.
  2. The frontmatter contains a non-empty `name:` field.
  3. The frontmatter contains a `description:` field of at least 40 characters.
  4. examples/ contains at least one `.md` file.

Prints "OK" and exits 0 on success; prints the failures and exits 1 otherwise.
"""

from __future__ import annotations

import sys
from pathlib import Path

MIN_DESCRIPTION_LEN = 40


def repo_root() -> Path:
    # scripts/ -> repo root
    return Path(__file__).resolve().parent.parent


def parse_frontmatter(text: str) -> dict[str, str] | None:
    """Extract a leading `---` ... `---` block into a flat key: value dict.

    Returns None if no well-formed frontmatter block is present.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None

    fm: dict[str, str] = {}
    closed = False
    for line in lines[1:]:
        if line.strip() == "---":
            closed = True
            break
        if ":" in line:
            key, _, value = line.partition(":")
            value = value.strip()
            # A YAML-quoted scalar ("..." or '...') means its contents, not the quotes.
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            fm[key.strip()] = value

    if not closed:
        return None
    return fm


def main() -> int:
    root = repo_root()
    errors: list[str] = []

    skill_path = root / "skill.md"
    if not skill_path.is_file():
        print("FAIL: skill.md not found")
        return 1

    text = skill_path.read_text(encoding="utf-8")
    fm = parse_frontmatter(text)

    if fm is None:
        errors.append("skill.md is missing a valid '---' frontmatter block")
    else:
        name = fm.get("name", "")
        if not name:
            errors.append("frontmatter is missing a non-empty 'name:' field")

        description = fm.get("description", "")
        if len(description) < MIN_DESCRIPTION_LEN:
            errors.append(
                "frontmatter 'description:' must be at least "
                f"{MIN_DESCRIPTION_LEN} characters (got {len(description)})"
            )

    examples_dir = root / "examples"
    md_examples = (
        sorted(examples_dir.glob("*.md")) if examples_dir.is_dir() else []
    )
    if not md_examples:
        errors.append("examples/ must contain at least one .md file")

    if errors:
        print("Skill validation FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    assert fm is not None  # for type-checkers; guaranteed by the checks above
    print("OK")
    print(f"  name: {fm.get('name')}")
    print(f"  description length: {len(fm.get('description', ''))} chars")
    print(f"  example files: {len(md_examples)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
