from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from obeliskscan.manifests.parsers import parse_package_json, parse_requirements_txt


class TestParsers(unittest.TestCase):
    def test_parse_requirements_txt(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "requirements.txt"
            p.write_text("requests==2.27.0\n# comment\nflask\n", encoding="utf-8")
            pkgs = parse_requirements_txt(p)
            self.assertEqual(pkgs[0]["name"], "requests")
            self.assertEqual(pkgs[0]["version"], "2.27.0")
            self.assertEqual(pkgs[1]["name"], "flask")

    def test_parse_package_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "package.json"
            p.write_text(
                json.dumps(
                    {
                        "dependencies": {"lodash": "4.17.15"},
                        "devDependencies": {"mocha": "8.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            pkgs = parse_package_json(p)
            names = {x["name"] for x in pkgs}
            self.assertIn("lodash", names)
            self.assertIn("mocha", names)

