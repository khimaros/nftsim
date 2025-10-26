# Contributing to nftsim

Essential context and commands for working on nftsim. For architecture, see [DESIGN.md](DESIGN.md).

## Bootstrap (First-time Setup)

Before running tests, you need to bootstrap the environment. This builds a custom UML kernel and creates a minimal Debian rootfs:

```bash
# Build nftsim
cargo build --release

# Run bootstrap (creates linux.uml kernel and rootfs.img)
./target/release/nftsim bootstrap
```

**What bootstrap does:**
- Builds custom UML kernel with all nftables features built-in (no modules needed)
- Caches kernel build in `$HOME/.local/share/nftsim/linux/` for fast incremental rebuilds
- Creates 2GB Debian bookworm rootfs with required packages (nftables, tcpdump, socat, etc.)
- Caches downloaded packages in `$HOME/.local/share/nftsim/rootfs-cache/` for fast rootfs recreation
- Only rebuilds kernel if `kernel.config` changes or binary is missing
- Prompts before recreating rootfs if one already exists

**Build artifacts** (all in `$HOME/.local/share/nftsim/` directory):
- `$HOME/.local/share/nftsim/linux/` - Kernel source and build artifacts (persistent cache)
- `$HOME/.local/share/nftsim/rootfs-cache/` - Debootstrap package cache (persistent)
- `$HOME/.local/share/nftsim/linux/linux` - Built UML kernel binary
- `$HOME/.local/share/nftsim/rootfs.img` - 2GB ext4 rootfs image

**Note:** Bootstrap uses Debian **bookworm** (stable) because forky/testing has a newer `mount` binary that uses the new mount API which is incompatible with UML's hostfs driver.

## Quick Build & Test

```bash
# Build
cargo build --release

# Run single test suite
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml

# Run all tests with live progress
./test.sh

# Run specific tests
./test.sh 01_basics 08_nat 22_ipv6

# Debug with verbose output
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml --verbose

# Debug with trace output (shows nftables rule evaluation)
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml --trace

# Debug with preserved temp directory (CRITICAL for analysis)
./target/release/nftsim test testdata/XX.nft testdata/XX.toml --keep-temp

# Analyze logs (use EXACT path from output, not wildcards!)
cat /tmp/.tmpXXXXXX/trace.log        # nftables trace output
cat /tmp/.tmpXXXXXX/test.log         # test execution log
cat /tmp/.tmpXXXXXX/guest_commands.log  # guest command output
```

## Test Suite Organization

| Suite                 | Tests | Description                                                    |
| --------------------- | ----- | -------------------------------------------------------------- |
| 01_basics             | 9     | TCP firewall fundamentals, concurrent connections, port ranges |
| 02_verdict_validation | 40    | Expectation validation framework (includes SHOULD_FAIL tests)  |
| 03_accept_verdict     | 4     | INPUT hook acceptance testing                                  |
| 04_udp                | 5     | UDP protocol support (DNS queries)                             |
| 05_icmp               | 5     | ICMP echo-request/reply (ping)                                 |
| 06_conntrack          | 10    | Connection tracking, state management, reuse                   |
| 07_mixed              | 12    | Multi-protocol scenarios, protocol transitions                 |
| 08_nat                | 9     | SNAT, DNAT, masquerade validation                              |
| 09_rate_limiting      | 6     | Rate limit rules (baseline tests)                              |
| 10_port_forwarding    | 7     | DNAT port forwarding scenarios                                 |
| 11_security           | 9     | Security policies, interface-based filtering                   |
| 12_dmz                | 13    | DMZ/3-zone firewall with zone-based policies                   |
| 13_sets               | 12    | nftables sets, intervals, maps                                 |
| 14_quotas             | 8     | Counters and quotas for traffic accounting                     |
| 15_stress             | 3     | High-volume stress testing (50+ connections)                   |
| 16_tcp_flags          | 9     | TCP flag validation (NULL, XMAS, invalid combos)               |
| 17_icmp_types         | 12    | Extended ICMP types, conntrack pollution                       |
| 18_ttl_validation     | 6     | TTL/hop limit validation                                       |
| 19_protocol_edge      | 8     | Protocol edge cases, multi-service validation                  |
| 20_advanced_nat       | 8     | Advanced NAT (port ranges, multi-interface)                    |
| 21_payload            | 9     | TCP/UDP/ICMP payload data support                              |
| 22_ipv6               | 5     | IPv6 dual-stack with automatic ICMP type translation           |
| 23_docker_host        | 25    | Docker host with VPN, NAT, container port forwarding           |
| 24_vpn_gateway        | 52    | VPN gateway with peer routing, masquerading, port forwarding   |
| 25_laptop             | 32    | Laptop/workstation firewall with selective service access      |
| 26_guest_injection    | 3     | OUTPUT and INPUT hooks with automatic guest injection          |

**Total: 26 test suites, 321 test cases**

The `test.sh` script provides:
- Live progress with colored output (green for pass, red for failures)
- Per-suite pass/fail summary
- Grand total statistics
- Exit code 0 on success, 1 on any failures
- Ctrl+C cleanup (kills UML processes on interrupt)

## Critical Code Locations

**Module structure** (`src/commands/test/`):
- `mod.rs` - Module coordinator
- `runner.rs` - Test orchestration and main execution loop
- `packet.rs` - Packet building with pnet_packet
- `trace.rs` - Trace parsing and TraceInfo struct
- `validation.rs` - Expectation validation logic
- `guest.rs` - Guest injection command building
- `setup.rs` - Environment setup and script generation

**Multi-line trace reading** (`src/commands/test/runner.rs::run_simulation()`):
- Each packet generates MULTIPLE trace lines (packet + rules + verdict)
- Must continue reading 100ms AFTER finding packet IPs to capture verdict lines
- Guest injection: 2s timeout with 100ms post-packet continuous read
- Host injection: 150ms continuous read from injection time
- Uses async `tokio::task::spawn_blocking` to read trace file

**Trace parsing** (`src/commands/test/trace.rs::parse_trace_for_packet()`):
- Matches packets by interface + IPs + ports
- Supports both IPv4 (`ip saddr/daddr`) and IPv6 (`ip6 saddr/daddr`)
- Returns `Option<TraceInfo>` with per-hook verdicts in HashMap
- Fallback matching by source IP + ports for conntrack de-NAT cases

**Message protocol** (`res/harness.sh` - command listener loop):
- Uses `sed -n "${line_num}p"` to read specific lines (avoids subshell scope issues)
- Shell parameter expansion: `${line%% *}` and `${line#* }` (no subshells)
- Line counting (`last_line` variable) prevents re-processing messages
- Polls `host_to_guest.txt` every 10ms

**Trace rule insertion** (`res/harness.sh` - dynamic chain discovery):
- Uses `nft list tables | while read` then `nft list table` to discover chains
- Inserts `meta nftrace set 1` at position 0 in ALL discovered chains
- Critical: Must process both `filter` and `nat` tables for NAT validation

**Packet building** (`src/commands/test/packet.rs::build_test_frame()`):
- Uses pnet_packet library for proper checksums
- Auto-detects IPv4 vs IPv6 from IP address format
- Calls `build_transport_layer()` for protocol-specific headers
- ICMP type auto-translation for IPv6 (type 8 → 128 for echo-request)

**Guest injection** (`src/commands/test/guest.rs`):
- `should_inject_from_guest()` - Determines if packet needs OUTPUT hook testing
- `build_guest_injection_command()` - Generates socat/ping commands
- Uses source IP matching to detect OUTPUT hook tests

**Verdict validation** (`src/commands/test/validation.rs::validate_expectations_from_trace()`):
- Primary: Use trace verdict from `TraceInfo.hook_verdicts` (authoritative)
- Fallback: Infer from packet capture for established connections
- NAT expectations: No fallback, trace must exist

## Common Pitfalls

### Conntrack State Pollution
**Problem:** Conntrack state persists across tests in same UML instance
**Solution:** Use unique IP pairs per test OR put drop/reject tests BEFORE connection-establishing tests
**Example:** `testdata/17_icmp_types.toml` (see comments)

### Subshell Variable Scope
**Wrong:** `tail -f file | while read line; do var=1; done` (var won't persist)
**Right:** `line=$(sed -n "${n}p" file)` + shell parameter expansion

### Missing NAT Table Trace
**Problem:** NAT expectations fail with "no NAT detected in trace"
**Solution:** Verify trace insertion loop includes `for table in filter nat; do`

### IPv6 ICMP Type Mismatch
**Problem:** Using `icmp type 8` instead of `icmpv6 type 128` in nftables rules
**Solution:** Use `icmpv6` for IPv6 addresses (nftsim auto-translates in tests)

### Trace Analysis with Wildcards
**Wrong:** `cat /tmp/.tmp*/trace.log` (might match old temp dirs)
**Right:** Use exact path from test output: `cat /tmp/.tmpXXXXXX/trace.log`

### Bootstrap with Wrong Debian Version
**Problem:** Using forky/testing causes "fsconfig() failed: Bad address" when mounting hostfs
**Root cause:** Forky's `mount` binary uses new mount API (fsconfig syscall) which UML's hostfs doesn't support
**Solution:** Always use **bookworm** (stable) - its mount binary still uses the legacy mount(2) syscall

## Debugging Workflow

1. Run with flags: `./target/release/nftsim test FILE.nft FILE.toml --keep-temp`
2. Check `test.log` for execution details
3. Check `trace.log` for nftables evaluation
4. Check `guest_commands.log` for guest command output
5. Verify ruleset syntax: `nft -c -f testdata/XX.nft`
6. Check for conntrack pollution (reorder tests if needed)

## Adding New Tests

1. Create `testdata/NN_name.nft` (ruleset)
2. Create `testdata/NN_name.toml` (test config)
3. Add to `test.sh` suites array
4. Test individually with `--verbose --trace` or `--keep-temp` for debugging
5. Run full suite: `./test.sh`
6. Update README.md test counts

**Test expectation fields:**
- `verdict`: accept/drop/reject (required)
- `hook`: Which nftables hook (optional, inferred from to_interface)
- `to_interface`: Expected output interface (optional, for FORWARD)
- `src_nat`: Expected SNAT address (optional, for POSTROUTING)
- `dst_nat`: Expected DNAT address (optional, for PREROUTING)

**Remember:**
- Use `[[tests.packets]]` table array syntax (not inline arrays)
- Use unique IP pairs if testing drop/reject after established connections
- Check for warnings: `cargo build --release 2>&1 | grep warning`

## Key Implementation Details

**All nftables features are built-in:** The custom kernel has all required netfilter features compiled as built-in (not modules). No module loading needed. This simplifies the guest boot process and ensures all features are always available.

**Trace is always enabled internally** (required for verdict validation), but only shown with `--trace` flag.

**Checksums are critical:** Use pnet_packet library. Invalid checksums = conntrack marks INVALID = dropped.

**Two injection modes:**
- **Host injection:** Direct socket write (for FORWARD/INPUT hooks)
- **Guest injection:** Execute command in guest via EXEC message (for OUTPUT hook)

**File-based control channel:**
- `host_to_guest.txt`: Commands (EXEC, SHUTDOWN)
- `guest_to_host.txt`: Responses (READY, ACK)
- 10ms polling interval
- Simple to debug: `tail -f /tmp/.tmpXXXXXX/host_to_guest.txt`

**IPv6 ICMP auto-translation:** Tests use ICMPv4 types (8 = echo-request), nftsim translates to ICMPv6 (128).

**Bootstrap caching:** Kernel builds are cached in `$HOME/.local/share/nftsim/linux/` for incremental rebuilds. Debootstrap packages are cached in `$HOME/.local/share/nftsim/rootfs-cache/` to speed up rootfs recreation. All build artifacts are in the `$HOME/.local/share/nftsim/` directory.

## Creating Custom Tests

### Test Definition Structure

Tests are defined in TOML files with three main sections:

```toml
# Network topology
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
]
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

# Guest setup (sysctls, pre/post commands)
[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# Test cases
[[tests]]
name = "HTTP Connection"

[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

### Supported Protocols

**TCP:**

```toml
tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] }
tcp = { source_port = 80, dest_port = 40000, flags = ["SYN", "ACK"] }
tcp = { source_port = 40000, dest_port = 80, flags = ["ACK"] }

# Optional payload data
tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"], payload = [0x47, 0x45, 0x54] }  # "GET"
```

**UDP:**

```toml
udp = { source_port = 53000, dest_port = 53 }

# Optional payload data
udp = { source_port = 53000, dest_port = 53, payload = [0x12, 0x34, 0x01, 0x00] }  # DNS header
```

**ICMP:**

```toml
icmp = { type = 8, code = 0 }  # Echo request (ping)
icmp = { type = 0, code = 0 }  # Echo reply
icmp = { type = 3, code = 0 }  # Destination unreachable
icmp = { type = 11, code = 0 } # Time exceeded

# Optional payload data
icmp = { type = 8, code = 0, payload = [0x61, 0x62, 0x63, 0x64] }
```

### Expectation Validation

Expectations use real nftables concepts:

```toml
# Forward hook with interface validation
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# Input hook (local delivery)
expect = [ { hook = "input", verdict = "accept" } ]

# NAT validation
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]

# Drop/reject
expect = [ { hook = "forward", verdict = "drop" } ]
```

### Hooks

- `prerouting` - NAT decisions before routing
- `input` - Local delivery to firewall
- `forward` - Packet forwarding between interfaces
- `output` - Packets originating from firewall
- `postrouting` - NAT decisions after routing

## Test Output Modes

**Normal** (default):

```
Running 5 test(s)...
  Allowed HTTP Connection from Internal ... ✓ PASS
  Blocked External to Internal Connection ... ✓ PASS
=== Test Summary ===
Total: 5  Passed: 5  Failed: 0
```

**Verbose** (`--verbose`):

- Shows UML boot output
- Displays packet injection details
- Shows byte counts and interface captures

**Trace** (`--trace`):

- Shows nftables trace output
- Displays rule evaluation for each packet
- Useful for debugging firewall behavior

**Keep Temp** (`--keep-temp`):

- Preserves temporary directory after test completion
- Enables manual inspection of logs (trace.log, test.log, guest_commands.log)
- Critical for debugging test failures

## Project Structure

```
nftsim/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── cli.rs               # Command definitions
│   ├── config.rs            # TOML configuration structs
│   └── commands/
│       ├── bootstrap.rs     # Bootstrap command (calls bootstrap.sh)
│       └── test/
│           ├── mod.rs       # Module coordinator
│           ├── runner.rs    # Test orchestration and main execution loop
│           ├── packet.rs    # Packet building with pnet_packet
│           ├── trace.rs     # Trace parsing and TraceInfo struct
│           ├── validation.rs # Expectation validation logic
│           ├── guest.rs     # Guest injection command building
│           └── setup.rs     # Environment setup and script generation
├── testdata/
│   ├── 01_basics.{nft,toml}
│   ├── 02_verdict_validation.{nft,toml}
│   └── ...                  # 26 test suites
├── res/
│   ├── harness.sh           # UML guest initialization script
│   ├── bootstrap.sh         # Kernel build and rootfs creation script
│   └── kernel.config        # UML kernel configuration
├── test.sh                  # Test runner with live progress
├── DESIGN.md                # Architecture documentation
├── CONTRIBUTING.md          # This file
└── README.md                # User-facing documentation

Build artifacts (in $HOME/.local/share/nftsim/):
├── linux/                   # Kernel source and build artifacts (persistent cache)
├── rootfs-cache/            # Debootstrap package cache (persistent)
├── linux/linux              # Built UML kernel binary
└── rootfs.img               # Root filesystem image (2GB ext4)
```

## Performance

- Build time: Fast (~10 seconds for release build)
- Test execution: 2-3 seconds per suite
- Full suite: ~2 minutes for all 321 tests

For architecture details, see DESIGN.md. For usage, see README.md.
