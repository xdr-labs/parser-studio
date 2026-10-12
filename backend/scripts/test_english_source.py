"""Regression guard for the owner-approved English-only Parser Studio policy.

Tests may use ASCII Unicode escapes to represent negative/non-ASCII inputs
without introducing non-English user-facing source text. Do not disable
internationalization safety tests to comply with the UI language policy.
"""
from pathlib import Path
import re
import subprocess
import unittest

PROJECT = Path(__file__).resolve().parents[2]
NON_ENGLISH = re.compile(r"[\uAC00-\uD7A3\u3040-\u30FF\u3400-\u9FFF]")
CHECKED_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".mjs", ".rb", ".json",
                      ".md", ".sh", ".yml", ".yaml", ".html", ".css"}


class EnglishSourceTests(unittest.TestCase):
    def test_tracked_backend_source_and_documentation_are_english_only(self):
        tracked = subprocess.check_output(
            ["git", "ls-files", "backend"], cwd=PROJECT, text=True
        ).splitlines()
        # Ensure a newly added source guard is checked even before it is staged.
        tracked.append("backend/scripts/test_english_source.py")
        violations = []
        for relative in sorted(set(tracked)):
            filename = PROJECT / relative
            if not filename.is_file() or filename.suffix not in CHECKED_EXTENSIONS:
                continue
            try:
                lines = filename.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                self.fail("Source is not valid UTF-8: " + relative)
            for line_number, line in enumerate(lines, 1):
                if NON_ENGLISH.search(line):
                    violations.append(f"{relative}:{line_number}")
        self.assertEqual([], violations)

    def test_negative_unicode_fixtures_remain_semantically_equivalent(self):
        import json

        fixture = PROJECT / "backend/test_native/fixtures/synthetic-golden.v0.1.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        # The JSON escape must decode back to exactly the original negative
        # RFC5424 test case: an invalid non-ASCII hostname, not a UI label.
        case = next(x for x in data["cases"]
                    if x["id"] == "rfc5424-nonascii-header")
        non_ascii = "".join(chr(cp) for cp in (0xD14C, 0xC2A4, 0xD2B8))
        self.assertIn(non_ascii, case["raw"])
        self.assertEqual(case["expectedRecord"]["parser_err_stage"], "extraction")
        self.assertIn(r"\uD14C", fixture.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
