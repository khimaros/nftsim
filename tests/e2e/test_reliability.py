"""end-to-end checks for instrument readiness, monitor liveness, and trace integrity."""

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from test_stability import NFTSIM

SIMPLE_DROP_NFT = textwrap.dedent("""\
    table inet filter {
        chain forward {
            type filter hook forward priority filter; policy drop;
        }
    }
""")

RATE_LIMIT_NFT = textwrap.dedent("""\
    table inet filter {
        chain forward {
            type filter hook forward priority filter; policy drop;
            iifname "eth0" oifname "eth1" tcp dport 80 limit rate 1/hour burst 1 packets accept
        }
    }
""")

# kill nft monitor trace using only POSIX sh + /proc (pkill is not in the minimal rootfs)
KILL_TRACE_MONITOR_CMD = (
    'for p in /proc/[0-9]*; do '
    'if grep -qa "monitor" "$p/cmdline" 2>/dev/null; then '
    'kill -9 "${p#/proc/}" 2>/dev/null || true; '
    'fi; done'
)


def run_inline_suite(nft_text, toml_text, extra_args=None, timeout=60):
    """write a temporary ruleset and config, run nftsim test, return CompletedProcess."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        nft_path = tmp_path / "rules.nft"
        toml_path = tmp_path / "suite.toml"
        nft_path.write_text(nft_text)
        toml_path.write_text(toml_text)
        cmd = [NFTSIM, "test", nft_path, toml_path, *(extra_args or [])]
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )


class ReliabilityTest(unittest.TestCase):
    def test_ready_timeout_is_hard_failure(self):
        """a guest that never signals READY must fail the run instead of proceeding."""
        toml = textwrap.dedent("""\
            [network]
            interfaces = [
              { name = "eth0", ip = "192.168.1.1/24" },
              { name = "eth1", ip = "10.0.0.1/24" },
            ]

            [guest_setup]
            sysctls = { "net.ipv4.ip_forward" = "1" }
            pre_nft_commands = ["sleep 20"]

            [[tests]]
            name = "empty expectation should not pass when guest never became ready"
            [[tests.packets]]
            packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "10.0.0.5", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
            expect = []
        """)
        proc = run_inline_suite(SIMPLE_DROP_NFT, toml, extra_args=["--timeout", "16"], timeout=30)
        combined = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0, combined)
        self.assertIn("READY", proc.stderr, combined)

    def test_dead_monitor_is_hard_failure(self):
        """if nft monitor trace dies before shutdown, the run must fail even without failing expectations."""
        toml = textwrap.dedent(f"""\
            [network]
            interfaces = [
              {{ name = "eth0", ip = "192.168.1.1/24" }},
              {{ name = "eth1", ip = "10.0.0.1/24" }},
            ]

            [guest_setup]
            sysctls = {{ "net.ipv4.ip_forward" = "1" }}
            post_nft_commands = ['{KILL_TRACE_MONITOR_CMD}']

            [[tests]]
            name = "empty expectation must still fail when trace monitor is dead"
            [[tests.packets]]
            packet = {{ on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "10.0.0.5", tcp = {{ source_port = 40000, dest_port = 80, flags = ["SYN"] }} }}
            expect = []
        """)
        proc = run_inline_suite(SIMPLE_DROP_NFT, toml)
        combined = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0, combined)
        self.assertIn("monitor", proc.stderr.lower(), combined)

    def test_dead_monitor_never_passes_drop_expectation(self):
        """a drop-only suite must exit non-zero when the trace monitor is killed."""
        toml = textwrap.dedent(f"""\
            [network]
            interfaces = [
              {{ name = "eth0", ip = "192.168.1.1/24" }},
              {{ name = "eth1", ip = "10.0.0.1/24" }},
            ]

            [guest_setup]
            sysctls = {{ "net.ipv4.ip_forward" = "1" }}
            post_nft_commands = ['{KILL_TRACE_MONITOR_CMD}']

            [[tests]]
            name = "drop must not pass blindly when monitor is dead"
            [[tests.packets]]
            packet = {{ on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "10.0.0.5", tcp = {{ source_port = 40000, dest_port = 80, flags = ["SYN"] }} }}
            expect = [ {{ hook = "forward", verdict = "drop" }} ]
        """)
        proc = run_inline_suite(SIMPLE_DROP_NFT, toml)
        combined = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0, combined)

    def test_repeated_five_tuple_uses_current_step_trace(self):
        """a second packet with the same 5-tuple must not match the first packet's trace."""
        toml = textwrap.dedent("""\
            [network]
            interfaces = [
              { name = "eth0", ip = "192.168.1.1/24" },
              { name = "eth1", ip = "10.0.0.1/24" },
            ]

            [guest_setup]
            sysctls = { "net.ipv4.ip_forward" = "1" }

            [[tests]]
            name = "rate limit allows first packet and drops identical second packet"
            [[tests.packets]]
            packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "10.0.0.5", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
            expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
            [[tests.packets]]
            packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "10.0.0.5", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
            expect = [ { hook = "forward", verdict = "drop" } ]
        """)
        proc = run_inline_suite(RATE_LIMIT_NFT, toml)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_unrecognized_trace_line_is_hard_failure(self):
        """any line in trace.log that does not match nft trace format must fail the run."""
        toml = textwrap.dedent("""\
            [network]
            interfaces = [
              { name = "eth0", ip = "192.168.1.1/24" },
              { name = "eth1", ip = "10.0.0.1/24" },
            ]

            [guest_setup]
            sysctls = { "net.ipv4.ip_forward" = "1" }
            post_nft_commands = ['echo "unexpected nft trace format v999" >> /mnt/host/trace.log']

            [[tests]]
            name = "drop case with malformed trace output"
            [[tests.packets]]
            packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "10.0.0.5", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
            expect = [ { hook = "forward", verdict = "drop" } ]
        """)
        proc = run_inline_suite(SIMPLE_DROP_NFT, toml)
        combined = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0, combined)
        self.assertIn("unrecognized", proc.stderr.lower(), combined)


if __name__ == "__main__":
    unittest.main()
