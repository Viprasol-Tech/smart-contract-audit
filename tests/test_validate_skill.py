import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from validate_skill import parse_frontmatter  # noqa: E402


class ParseFrontmatterTest(unittest.TestCase):
    def test_quoted_values_are_unquoted(self):
        fm = parse_frontmatter('---\nname: "audit"\ndescription: \'short\'\n---\n')
        self.assertEqual(fm, {"name": "audit", "description": "short"})

    def test_quoted_empty_name_is_empty(self):
        fm = parse_frontmatter('---\nname: ""\n---\n')
        self.assertEqual(fm["name"], "")

    def test_plain_values_unchanged(self):
        fm = parse_frontmatter("---\nname: smart-contract-audit\n---\n")
        self.assertEqual(fm["name"], "smart-contract-audit")


if __name__ == "__main__":
    unittest.main()
