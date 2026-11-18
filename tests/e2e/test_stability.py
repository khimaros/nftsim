"""end-to-end checks that suites pass reliably outside an idle, single-run host."""

import multiprocessing
import os
import subprocess
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NFTSIM = ROOT / "target" / "release" / "nftsim"
TESTDATA = ROOT / "testdata"
RUN_TIMEOUT_SECS = 300
# 24_vpn_gateway has the most host-injected cases, so it is the most
# sensitive to trace latency
LOAD_SUITE = "24_vpn_gateway"
LOAD_SECS = 120


def run_suite(name):
    """run one testdata suite, returning the completed process."""
    return subprocess.run(
        [NFTSIM, "test", TESTDATA / f"{name}.nft", TESTDATA / f"{name}.toml"],
        capture_output=True, text=True, timeout=RUN_TIMEOUT_SECS, check=False,
    )


def burn(seconds):
    """keep one core busy, standing in for a loaded CI host."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pass


class StabilityTest(unittest.TestCase):
    def assertPassed(self, proc):
        """fail with the run's output so a flaky case can be diagnosed."""
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_concurrent_runs(self):
        """two runs at once must not fight over the shared rootfs image."""
        with ThreadPoolExecutor(2) as pool:
            procs = list(pool.map(run_suite, ["01_basics", "03_accept_verdict"]))
        for proc in procs:
            self.assertPassed(proc)

    def test_run_under_cpu_load(self):
        """trace collection must wait for slow guests instead of a fixed window."""
        burners = [multiprocessing.Process(target=burn, args=(LOAD_SECS,), daemon=True)
                   for _ in range(os.cpu_count() or 1)]
        for b in burners:
            b.start()
        try:
            self.assertPassed(run_suite(LOAD_SUITE))
        finally:
            for b in burners:
                b.terminate()


if __name__ == "__main__":
    unittest.main()
