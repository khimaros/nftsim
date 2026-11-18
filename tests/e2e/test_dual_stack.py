"""end-to-end checks for interfaces that carry addresses of both families."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_stability import NFTSIM, RUN_TIMEOUT_SECS

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class DualStackTest(unittest.TestCase):
    def test_dual_stack_suite(self):
        """masquerade and guest injection must use every configured address."""
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            proc = subprocess.run(
                [NFTSIM, "test", FIXTURES / "dual_stack.toml", "--report", report_path],
                capture_output=True, text=True, timeout=RUN_TIMEOUT_SECS, check=False,
            )
            self.assertTrue(report_path.exists(), proc.stdout + proc.stderr)
            report = json.loads(report_path.read_text())
        cases = [t for s in report["suites"] for t in s["tests"]]
        self.assertEqual(len(cases), 3, proc.stdout + proc.stderr)
        for case in cases:
            with self.subTest(case["name"]):
                self.assertTrue(case["passed"], case["reason"])


if __name__ == "__main__":
    unittest.main()
