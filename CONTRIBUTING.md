# contributing to nftsim

context and commands for working on nftsim. for architecture, see [DESIGN.md](DESIGN.md).

## bootstrap (first-time setup)

tests need a custom UML kernel and a minimal Debian rootfs:

```bash
# build nftsim
cargo build --release

# build the UML kernel and rootfs.img
./target/release/nftsim bootstrap
```

bootstrap:
- builds a custom UML kernel with every nftables feature built in (no modules)
- creates a 2GB Debian bookworm rootfs with the required packages (nftables, tcpdump, socat, etc.)
- rebuilds the kernel only if `kernel.config` changes or the binary is missing
- prompts before recreating an existing rootfs

build artifacts, all in `$HOME/.local/share/nftsim/`:
- `linux/` - kernel source and build artifacts (persistent cache for incremental rebuilds)
- `linux/linux` - built UML kernel binary
- `rootfs-cache/` - debootstrap package cache (persistent)
- `rootfs.img` - 2GB ext4 rootfs image

bootstrap uses Debian **bookworm** because the `mount` binary in forky/testing uses the new mount API, which UML's hostfs driver does not support (see pitfalls below).

## build and test

```bash
# build
make

# run a single test suite
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml

# run all suites with live progress
./test.sh

# run specific suites
./test.sh 01_basics 08_nat 22_ipv6

# end-to-end stability tests
make test-e2e

# linters and static analysis
make precommit

# verbose output
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml --verbose

# trace output (shows nftables rule evaluation)
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml --trace

# keep the temp directory for analysis
./target/release/nftsim test testdata/XX.nft testdata/XX.toml --keep-temp

# analyze logs (use the EXACT path from the output, not wildcards)
cat /tmp/.tmpXXXXXX/trace.log        # nftables trace output
cat /tmp/.tmpXXXXXX/test.log         # test execution log
cat /tmp/.tmpXXXXXX/harness.log      # guest boot log
cat /tmp/.tmpXXXXXX/commands.log     # guest command output
```

## test suite organization

| suite                  | tests | description                                                    |
| ---------------------- | ----- | -------------------------------------------------------------- |
| 01_basics              | 9     | TCP firewall basics, concurrent connections, port ranges       |
| 02_verdict_validation  | 40    | expectation validation framework (includes SHOULD_FAIL tests)  |
| 03_accept_verdict      | 4     | INPUT hook acceptance                                          |
| 04_udp                 | 5     | UDP protocol support (DNS queries)                             |
| 05_icmp                | 5     | ICMP echo-request/reply (ping)                                 |
| 06_conntrack           | 10    | connection tracking, state management, reuse                   |
| 07_mixed               | 12    | multi-protocol scenarios, protocol transitions                 |
| 08_nat                 | 9     | SNAT, DNAT, masquerade                                         |
| 09_rate_limiting       | 6     | rate limit rules (baseline tests)                              |
| 10_port_forwarding     | 7     | DNAT port forwarding                                           |
| 11_security            | 9     | security policies, interface-based filtering                   |
| 12_dmz                 | 13    | DMZ/3-zone firewall with zone-based policies                   |
| 13_sets                | 12    | nftables sets, intervals, maps                                 |
| 14_quotas              | 8     | counters and quotas for traffic accounting                     |
| 15_stress              | 3     | high-volume stress testing (50+ connections)                   |
| 16_tcp_flags           | 9     | TCP flag validation (NULL, XMAS, invalid combinations)         |
| 17_icmp_types          | 12    | extended ICMP types, conntrack pollution                       |
| 18_ttl_validation      | 6     | TTL/hop limit validation                                       |
| 19_protocol_edge_cases | 8     | protocol edge cases, multi-service validation                  |
| 20_advanced_nat        | 8     | NAT port ranges, multi-interface NAT                           |
| 21_payload             | 9     | TCP/UDP/ICMP payload data                                      |
| 22_ipv6                | 5     | IPv6 dual-stack with automatic ICMP type translation           |
| 23_docker_host         | 25    | Docker host with VPN, NAT, container port forwarding           |
| 24_vpn_gateway         | 52    | VPN gateway with peer routing, masquerading, port forwarding   |
| 25_laptop              | 32    | laptop/workstation firewall with selective service access      |
| 26_guest_injection     | 3     | OUTPUT and INPUT hooks with automatic guest injection          |

**total: 26 test suites, 321 test cases**

`test.sh` shows live colored progress, a pass/fail summary per suite and a grand total. it exits 1 on any failure and kills UML processes on Ctrl+C.

## key code locations

**module structure** (`src/commands/test/`):
- `mod.rs` - module coordinator
- `runner.rs` - test orchestration and main execution loop
- `packet.rs` - packet building with pnet_packet
- `trace.rs` - trace parsing and the TraceInfo struct
- `validation.rs` - expectation validation
- `guest.rs` - guest injection command building
- `setup.rs` - environment setup and script generation
- `report.rs` - JSON results for `--report`
- `embedded.rs` - test definitions embedded in ruleset comments

**multi-line trace reading** (`src/commands/test/runner.rs::run_simulation()`):
- each packet generates MULTIPLE trace lines (packet, rules, verdict)
- `collect_packet_trace()` reads until `parse_trace_for_packet()` matches, then until the trace has been quiet for 150ms
- it gives up after 3s for packets that never show up; never use a fixed read window, since a loaded host delays trace lines
- `harness.sh` holds READY until `nft monitor trace` has joined the trace netlink group, or the first packet goes untraced

**end-to-end tests** (`tests/e2e/`, run with `make test-e2e`):
- two concurrent runs (shared rootfs image, per-run COW overlay)
- 24_vpn_gateway with every core busy (trace latency)
- a dual-stack gateway (`fixtures/dual_stack.toml`): several addresses per interface, guest injection from a second address, masquerade read from conntrack

**trace parsing** (`src/commands/test/trace.rs::parse_trace_for_packet()`):
- matches packets by interface, IPs and ports
- supports IPv4 (`ip saddr/daddr`) and IPv6 (`ip6 saddr/daddr`)
- returns `Option<TraceInfo>` with per-hook verdicts in a HashMap
- falls back to source IP and ports for conntrack de-NAT

**message protocol** (`res/harness.sh` command listener loop):
- reads specific lines with `sed -n "${line_num}p"` to avoid subshell scope issues
- splits messages with `${line%% *}` and `${line#* }` (no subshells)
- the `last_line` counter prevents re-processing messages
- polls `host_to_guest.txt` every 10ms

**trace rule insertion** (`res/harness.sh` dynamic chain discovery):
- runs `nft list tables | while read`, then `nft list table` to discover chains
- inserts `meta nftrace set 1` at the start of EVERY discovered chain, across all tables, so NAT chains are traced too

**packet building** (`src/commands/test/packet.rs::build_test_frame()`):
- uses pnet_packet for correct checksums
- detects IPv4 or IPv6 from the address format
- calls `build_transport_layer()` for protocol headers
- translates ICMP types for IPv6 (type 8 -> 128 for echo-request)

**guest injection** (`src/commands/test/guest.rs`):
- `should_inject_from_guest()` decides whether a packet needs OUTPUT hook testing, by matching the source IP against every configured interface address
- `build_guest_injection_command()` generates socat/ping commands

**verdict validation** (`src/commands/test/validation.rs::validate_expectations_from_trace()`):
- uses only the trace: verdicts from `TraceInfo.hook_verdicts`, the output interface from the trace `oif`
- a packet missing from the trace fails the step

## common pitfalls

### conntrack state pollution
**problem:** conntrack state persists across tests in the same UML instance.
**solution:** use unique IP pairs per test, or put drop/reject tests BEFORE connection-establishing tests.
**example:** `testdata/17_icmp_types.toml` (see comments)

### subshell variable scope
**wrong:** `tail -f file | while read line; do var=1; done` (var won't persist)
**right:** `line=$(sed -n "${n}p" file)` plus shell parameter expansion

### missing NAT trace
**problem:** NAT expectations fail with "no NAT detected in trace".
**solution:** check `harness.log` for chains where trace insertion failed.

### IPv6 ICMP type mismatch
**problem:** using `icmp type 8` instead of `icmpv6 type 128` in nftables rules.
**solution:** use `icmpv6` for IPv6 addresses (nftsim translates the types in tests).

### trace analysis with wildcards
**wrong:** `cat /tmp/.tmp*/trace.log` (might match old temp dirs)
**right:** use the exact path from the test output: `cat /tmp/.tmpXXXXXX/trace.log`

### bootstrap with the wrong Debian version
**problem:** forky/testing causes "fsconfig() failed: Bad address" when mounting hostfs.
**root cause:** forky's `mount` binary uses the new mount API (fsconfig syscall), which UML's hostfs does not support.
**solution:** always use **bookworm**, whose mount binary still uses the legacy mount(2) syscall.

## debugging workflow

1. run with `./target/release/nftsim test FILE.nft FILE.toml --keep-temp`
2. check `test.log` for execution details
3. check `trace.log` for nftables evaluation
4. check `harness.log` and `commands.log` for guest output
5. verify ruleset syntax: `nft -c -f testdata/XX.nft`
6. check for conntrack pollution (reorder tests if needed)

## adding new tests

1. create `testdata/NN_name.nft` (ruleset)
2. create `testdata/NN_name.toml` (test config)
3. add it to the `test.sh` suites array
4. run it alone with `--verbose --trace` or `--keep-temp`
5. run all suites: `./test.sh`
6. update the test counts in README.md and this file

**expectation fields:**
- `verdict`: accept/drop/reject (required)
- `hook`: nftables hook (optional, inferred from to_interface)
- `to_interface`: expected output interface (optional, for FORWARD)
- `src_nat`: expected SNAT address (optional, for POSTROUTING)
- `dst_nat`: expected DNAT address (optional, for PREROUTING)

**remember:**
- use `[[tests.packets]]` table array syntax (not inline arrays)
- use unique IP pairs when testing drop/reject after established connections
- run `make precommit` before submitting

## key implementation details

**nftables features are built in:** the custom kernel compiles every required netfilter feature in rather than as modules, so the guest never loads modules.

**trace is always enabled internally** (verdict validation needs it), but only shown with `--trace`.

**checksums matter:** use pnet_packet. an invalid checksum makes conntrack mark the packet INVALID, and it is dropped.

**injection modes:**
- **host injection:** direct socket write (FORWARD/INPUT hooks)
- **guest injection:** a command run in the guest via an EXEC message (OUTPUT hook)

**file-based control channel:**
- `host_to_guest.txt`: commands (EXEC, SHUTDOWN)
- `guest_to_host.txt`: responses (READY, ACK)
- 10ms polling interval
- easy to follow: `tail -f /tmp/.tmpXXXXXX/host_to_guest.txt`

**IPv6 ICMP translation:** tests use ICMPv4 types (8 = echo-request), nftsim translates them to ICMPv6 (128).

## creating custom tests

### test definition structure

TOML test files have three sections:

```toml
# network topology
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
]
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

# guest setup (sysctls, pre/post commands)
[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# test cases
[[tests]]
name = "HTTP Connection"

[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

### supported protocols

**TCP:**

```toml
tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] }
tcp = { source_port = 80, dest_port = 40000, flags = ["SYN", "ACK"] }
tcp = { source_port = 40000, dest_port = 80, flags = ["ACK"] }

# optional payload data
tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"], payload = [0x47, 0x45, 0x54] }  # "GET"
```

**UDP:**

```toml
udp = { source_port = 53000, dest_port = 53 }

# optional payload data
udp = { source_port = 53000, dest_port = 53, payload = [0x12, 0x34, 0x01, 0x00] }  # DNS header
```

**ICMP:**

```toml
icmp = { type = 8, code = 0 }  # echo request (ping)
icmp = { type = 0, code = 0 }  # echo reply
icmp = { type = 3, code = 0 }  # destination unreachable
icmp = { type = 11, code = 0 } # time exceeded

# optional payload data
icmp = { type = 8, code = 0, payload = [0x61, 0x62, 0x63, 0x64] }
```

### expectations

expectations use nftables hooks and verdicts:

```toml
# forward hook with interface validation
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# input hook (local delivery)
expect = [ { hook = "input", verdict = "accept" } ]

# NAT validation
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]

# drop/reject
expect = [ { hook = "forward", verdict = "drop" } ]
```

### hooks

- `prerouting` - NAT decisions before routing
- `input` - local delivery to the firewall
- `forward` - forwarding between interfaces
- `output` - packets originating from the firewall
- `postrouting` - NAT decisions after routing

## test output modes

**normal** (default):

```
running 5 test(s)...
  allowed HTTP connection from internal ... pass
  blocked external to internal connection ... pass
=== test summary ===
total: 5  passed: 5  failed: 0
```

**verbose** (`--verbose`): UML boot output, packet injection details, byte counts and interface captures.

**trace** (`--trace`): nftables trace output with the rule evaluation for each packet.

**keep temp** (`--keep-temp`): keeps the temporary directory after the run so the logs (trace.log, test.log, harness.log, commands.log) can be inspected.

## project structure

```
nftsim/
|-- src/
|   |-- main.rs              # CLI entry point
|   |-- cli.rs               # command definitions
|   |-- config.rs            # TOML configuration structs
|   |-- resources.rs         # resources embedded at compile time
|   `-- commands/
|       |-- bootstrap.rs     # bootstrap command (runs bootstrap.sh)
|       `-- test/
|           |-- mod.rs       # module coordinator
|           |-- runner.rs    # test orchestration and main execution loop
|           |-- packet.rs    # packet building with pnet_packet
|           |-- trace.rs     # trace parsing and the TraceInfo struct
|           |-- validation.rs # expectation validation
|           |-- guest.rs     # guest injection command building
|           |-- setup.rs     # environment setup and script generation
|           |-- report.rs    # JSON results for --report
|           `-- embedded.rs  # tests embedded in ruleset comments
|-- testdata/
|   |-- 01_basics.{nft,toml}
|   |-- 02_verdict_validation.{nft,toml}
|   `-- ...                  # 26 test suites
|-- tests/e2e/               # Python end-to-end stability tests
|-- res/
|   |-- harness.sh           # UML guest initialization script
|   |-- bootstrap.sh         # kernel build and rootfs creation script
|   `-- kernel.config        # UML kernel configuration
|-- Makefile                 # build, test, test-e2e, precommit
|-- test.sh                  # test runner with live progress
|-- DESIGN.md                # architecture documentation
|-- TESTDATA.md              # TOML format reference
|-- CONTRIBUTING.md          # this file
`-- README.md                # user-facing documentation

build artifacts (in $HOME/.local/share/nftsim/):
|-- linux/                   # kernel source and build artifacts (persistent cache)
|-- linux/linux              # built UML kernel binary
|-- rootfs-cache/            # debootstrap package cache (persistent)
`-- rootfs.img               # root filesystem image (2GB ext4)
```

## performance

- release build: about 10 seconds
- test execution: 2-3 seconds per suite
- all suites: about 2 minutes for 321 tests
