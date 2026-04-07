from __future__ import annotations

import unittest

from obeliskscan.reporting.sanitize import csv_safe, sanitize_target_name


class TestSanitize(unittest.TestCase):
    def test_csv_safe_prefixes_formula(self):
        self.assertEqual(csv_safe("=1+1"), "'=1+1")
        self.assertEqual(csv_safe(" +SUM(A1:A2)"), "' +SUM(A1:A2)")
        self.assertEqual(csv_safe("normal"), "normal")

    def test_sanitize_target_name_blocks_windows_traversal(self):
        # Backslashes/path components should be removed.
        self.assertEqual(sanitize_target_name(r"..\..\evil"), "evil")

