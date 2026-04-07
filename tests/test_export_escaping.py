from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from obeliskscan.reporting.export import export_html


class TestExportEscaping(unittest.TestCase):
    def test_export_html_escapes_untrusted_fields(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "r.html"
            packages = [{"name": "<img src=x onerror=1>", "version": "1"}]
            results = [
                (
                    packages[0],
                    [
                        {
                            "cve_id": "CVE-1",
                            "severity": "HIGH",
                            "description": "<script>alert(1)</script>",
                            "fix_version": "N/A",
                            "source": "OSV",
                        }
                    ],
                )
            ]
            export_html(out, packages, results, duration=0.1)
            html_text = out.read_text(encoding="utf-8")
            self.assertIn("&lt;img", html_text)
            self.assertIn("&lt;script&gt;", html_text)
            self.assertNotIn("<script>alert(1)</script>", html_text)

