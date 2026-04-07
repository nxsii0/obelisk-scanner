from __future__ import annotations

import unittest
from unittest.mock import patch

from obeliskscan.providers.http import HttpPolicy
from obeliskscan.providers.nvd import query_nvd
from obeliskscan.providers.osv import query_osv


class TestProvidersMock(unittest.TestCase):
    def test_query_osv_parses_basic(self):
        policy = HttpPolicy(timeout_sec=1, verify_tls=True)
        fake = {
            "vulns": [
                {
                    "id": "OSV-1",
                    "aliases": ["CVE-2020-0001"],
                    "summary": "Example vuln",
                    "severity": [{"score": "HIGH"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "1.2.3"}]}]}],
                }
            ]
        }
        with patch("obeliskscan.providers.osv.get_json", return_value=(200, fake)):
            res = query_osv({"name": "x", "version": "1.0.0", "ecosystem": "PyPI"}, policy=policy)
            self.assertEqual(res[0]["cve_id"], "CVE-2020-0001")
            self.assertEqual(res[0]["severity"], "HIGH")
            self.assertEqual(res[0]["fix_version"], "1.2.3")

    def test_query_nvd_parses_basic(self):
        policy = HttpPolicy(timeout_sec=1, verify_tls=True)
        fake = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-0002",
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                        "descriptions": [{"lang": "en", "value": "desc"}],
                    }
                }
            ]
        }
        with patch("obeliskscan.providers.nvd.get_json", return_value=(200, fake)):
            res = query_nvd({"name": "x", "version": "1.0.0"}, policy=policy)
            self.assertEqual(res[0]["cve_id"], "CVE-2021-0002")
            self.assertEqual(res[0]["severity"], "CRITICAL")

