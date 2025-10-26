# DESIGN.md: nftsim Architecture and Design

This document outlines the design and architecture of the `nftsim` tool. It serves as a technical blueprint for development.

## 1. Core Principles & Workflow

`nftsim` is a command-line tool designed to provide a high-fidelity, unprivileged, and observable simulation environment for nftables rulesets.

The core workflow is as follows:

1.  A user invokes `nftsim test <RULESET_PATH> <CONFIG_TOML_1> [CONFIG_TOML_2...] [--trace] [--verbose]`.
2.  For each config file, the tool parses the test definition, which specifies the virtual network topology, kernel parameters, and a series of stateful test sequences.
3.  It prepares a temporary staging directory for the simulation run.
4.  It generates a dynamic startup script (`run-sim.sh`) based on the network and guest setup configuration.
5.  It creates Unix socketpairs for each network interface to enable unprivileged packet injection.
6.  It launches a User-Mode Linux (UML) kernel instance with `fd` transport for network interfaces.
7.  The UML instance boots and executes the startup script, which configures networking, sysctls, loads the nftables ruleset, and optionally enables trace monitoring.
8.  The orchestrator injects test packets directly through Unix sockets, building proper Ethernet/IP/TCP frames with valid checksums.
9.  The firewall processes packets with full connection tracking support.
10. When `--trace` is enabled, nftables trace data is captured showing rule evaluation and verdicts.
11. After all tests complete, results are displayed showing PASS/FAIL for each test case.

## 2. Test Definition (`config.toml`)

### 2.0. Expectation Model Philosophy

The expectation model uses **actual nftables concepts** to make tests clear and maintainable:

- **Hook-based**: Tests specify which nftables hook processes the packet (input, forward, output, etc.)
- **Real verdicts**: Uses actual nftables verdicts (accept, drop, reject) not synthetic ones
- **Separation of concerns**: Verdict (what nftables decides) is separate from routing (where packet goes)
- **Interface validation**: `to_interface` validates packet forwarding independently of verdict
- **Extensible**: Ready for NAT validation (`src_nat`, `dst_nat`) and other operational checks

**Example:**

```toml
# Clear: packet accepted at forward hook, exits on eth1
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# Clear: packet accepted at input hook (delivered locally)
expect = [ { hook = "input", verdict = "accept" } ]

# Future: NAT validation
expect = [ { hook = "postrouting", verdict = "accept", src_nat = "10.0.0.1" } ]
```

## 2.1. Test Definition (`config.toml`)

To ensure simulations are repeatable and self-contained, the entire test environment is defined in a single TOML file. The tool can accept multiple such files to run a suite of tests.

### 2.2. TOML Structure

The file has three main sections: `[network]` for topology, `[guest_setup]` for kernel and command configuration, and an array of `[[tests]]` for the packet sequences.

**Note**: Each test uses `[[tests.packets]]` table arrays to define packet steps, rather than inline arrays. This TOML syntax provides better readability for multi-packet test scenarios.

```toml
# config.toml

# Defines the network topology for the UML guest.
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
]

# Defines static routes for the guest.
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

# Defines the setup procedure for the guest environment.
[guest_setup]
# A map of sysctl key-value pairs to set.
sysctls = { "net.ipv4.ip_forward" = "1" }

# Custom shell commands to run after networking is up, but BEFORE the nftables ruleset is loaded.
pre_nft_commands = [
  "echo 'Loading conntrack...'",
  "modprobe nf_conntrack || echo 'conntrack may be built-in'"
]

# Custom shell commands to run AFTER the nftables ruleset is loaded.
post_nft_commands = [
  "echo '=== Loaded nftables ruleset ==='",
  "nft list ruleset"
]


# Defines the test cases. Each test case is a sequence of packet steps.
[[tests]]
name = "Allowed HTTP Connection from Internal"

# Each packet step is defined using [[tests.packets]]
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 32768, dest_port = 80, flags = ["SYN"] } }
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

[[tests.packets]]
packet = { on_interface = "eth1", source_ip = "8.8.8.8", dest_ip = "192.168.1.50", tcp = { source_port = 80, dest_port = 32768, flags = ["SYN", "ACK"] } }
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth0" } ]

[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 32768, dest_port = 80, flags = ["ACK"] } }
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

[[tests]]
name = "Blocked Connection to Disallowed Port"

[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 50000, dest_port = 25, flags = ["SYN"] } }
expect = [ { hook = "forward", verdict = "drop" } ]

[[tests]]
name = "Blocked External to Internal Connection"

[[tests.packets]]
packet = { on_interface = "eth1", source_ip = "1.2.3.4", dest_ip = "192.168.1.50", tcp = { source_port = 12345, dest_port = 80, flags = ["SYN"] } }
expect = [ { hook = "forward", verdict = "drop" } ]
```

### 2.3. Implementation in Rust

- **`src/config.rs`**: This module defines the Rust structs (`SimConfig`, `Network`, `GuestSetup`, `TestCase`, `PacketStep`, etc.) that mirror the TOML structure. They derive `serde::Deserialize`.
- **`clap`**: The `test` command in `src/cli.rs` accepts one positional argument for the ruleset, a variable number of positional arguments for config files, and optional `--trace` and `--verbose` flags.
- **Lowercase Verdicts**: A custom `Verdict` enum (`Accept`, `Drop`, `Reject`) implements `serde::Deserialize` with a custom function that accepts only lowercase strings, enforcing the convention.
- **Expectation Validation**: The `expect` field uses actual nftables verdicts with hook awareness:
  - **Verdict Types**: `accept`, `drop`, `reject` (matches actual nftables verdicts)
  - **Hook Field**: Specifies which nftables hook (input, forward, output, prerouting, postrouting)
  - **Interface Validation**: `to_interface` specifies expected output interface for forwarded packets
  - **Hybrid Validation**: Combines nft trace (authoritative verdict) with socket capture (interface verification)
  - **NAT Validation**: `src_nat` and `dst_nat` fields validate SNAT/DNAT/masquerade address transformations
    - Parses trace output for `snat to`, `snat ip to`, `dnat to`, `dnat ip to`, and `masquerade`
    - For masquerade rules, infers SNAT IP from output interface address

## 3. Component Breakdown

### 3.1. The Rust Orchestrator (`nftsim`)

- **`commands/test.rs`**: The core simulation logic.
  1.  **Parsing**: Loops through each provided config file path, reading and parsing the TOML into a `SimConfig` struct.
  2.  **Guest Script Execution**: Executes standalone `harness.sh` script with dynamic chain discovery and trace rule insertion.
  3.  **Socketpair Creation**: Creates Unix socketpairs for each network interface using `UnixStream::pair()`.
  4.  **UML Launch**: Spawns UML with `vec<N>:transport=fd,fd=<FD>,mac=<MAC>` arguments, using `pre_exec` to dup2 the socket file descriptors.
  5.  **Trace Enablement**: harness.sh discovers all chains and inserts `meta nftrace set 1` at position 0, starts `nft monitor trace`.
  6.  **Packet Injection**: Builds complete Ethernet frames using pnet_packet library (IPv4/IPv6 support), writes frames to Unix sockets.
  7.  **Trace Parsing**: Reads trace.log and extracts per-hook verdicts by matching packet IPs/ports, with fallback for conntrack de-NAT.
  8.  **Trace-Only Validation**: Uses nftables trace as single source of truth (no socket capture timing dependencies).
  9.  **Per-Hook Verdict Tracking**: Validates specific hooks in packet's journey (PREROUTING → FORWARD → POSTROUTING).
  10. **NAT Validation**: Extracts SNAT/DNAT from trace, resolves masquerade using packet line oif with fallback to rule line oifname.
  11. **Logging**: Always writes verbose logs to test.log and trace.log, captures UML stdout/stderr, supports --keep-temp for analysis.
  12. **Result Display**: Shows clean test results with PASS/FAIL status. In `--trace` mode, displays the full trace log.

### 3.2. The UML Guest Environment

- **Standalone Script (`harness.sh`)**: A standalone shell script that executes inside the guest for environment setup.
  1.  Run `pre_nft_commands` if present.
  2.  Load the user's nftables ruleset (`nft -f /mnt/host/rules.nft`).
  3.  **Dynamic Chain Discovery**: Parse `nft list tables` output to discover all tables and chains.
  4.  **Trace Rule Insertion**: Insert `meta nftrace set 1` at position 0 in ALL discovered chains (handles any chain names).
  5.  Start `nft monitor trace > /mnt/host/trace.log &` in background.
  6.  Run `post_nft_commands` if present.
  7.  **Message Protocol Loop**: Poll `host_to_guest.txt` for EXEC and SHUTDOWN messages.
  8.  Kill trace monitor and sync before halt.

- **Dynamic Startup Script (`entrypoint.sh`)**: Generated by Rust, configures the guest environment.
  1.  Mount `/proc`, `/sys`, and hostfs at `/mnt/host`.
  2.  Rename vector interfaces from `vec0`, `vec1`, etc. to their configured names (`eth0`, `eth1`).
  3.  Configure network interfaces with IP addresses (`ip addr add`, `ip link set up`).
  4.  Set `sysctl` values.
  5.  Configure routes (`ip route add`).
  6.  Execute `harness.sh` for nftables setup and trace enablement.
  7.  Sync and halt cleanly using `halt -f`.

### 3.3. Control Channel and Message Protocol

**Current Implementation (File-Based)**:

The host and guest communicate using append-only message log files:
- `host_to_guest.txt`: Commands from orchestrator to guest (EXEC, SHUTDOWN)
- `guest_to_host.txt`: Responses from guest to orchestrator (READY, ACK)

**Message Protocol**:
- **Line-based**: Each message is one line, newline-delimited
- **Space-delimited**: First word is message type, rest is payload
- **Format**: `TYPE payload data here\n`

**Host → Guest Messages**:
```
EXEC <command>     # Execute shell command in guest
SHUTDOWN           # Request graceful shutdown
```

**Guest → Host Messages**:
```
READY              # Guest boot complete, ready for commands
ACK <exit_code>    # Command execution completed with exit code
```

**Implementation Details**:

Guest message listener (in `harness.sh`):
```bash
# Track last read line number to avoid re-processing
last_line=0
shutdown_received=0

while [ "$shutdown_received" -eq 0 ]; do
  if [ -f /mnt/host/host_to_guest.txt ]; then
    current_lines=$(wc -l < /mnt/host/host_to_guest.txt)

    if [ "$current_lines" -gt "$last_line" ]; then
      # Process each new line using sed (avoids subshell issues)
      line_num=$((last_line + 1))
      while [ "$line_num" -le "$current_lines" ]; do
        line=$(sed -n "${line_num}p" /mnt/host/host_to_guest.txt)

        # Split on first space
        msg_type="${line%% *}"
        msg_data="${line#* }"

        case "$msg_type" in
          EXEC)
            eval "$msg_data" >> /mnt/host/guest_commands.log 2>&1
            exit_code=$?
            echo "ACK $exit_code" >> /mnt/host/guest_to_host.txt
            ;;
          SHUTDOWN)
            echo "ACK 0" >> /mnt/host/guest_to_host.txt
            shutdown_received=1
            ;;
        esac

        line_num=$((line_num + 1))
      done
      last_line=$current_lines
    fi
  fi

  sleep 0.01  # Fast polling - 10ms
done
```

Host message sending (in `test.rs`):
```rust
// Append EXEC message
let message = format!("EXEC {}\n", cmd);
std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(&host_to_guest_path)?
    .write_all(message.as_bytes())?;

// Wait for ACK response by counting ACK lines in guest_to_host.txt
```

**Benefits**:
- Simple append-only files (easy to debug with `tail -f`)
- Natural message ordering
- Line counting avoids re-processing messages
- No complex synchronization primitives

**Limitations**:
- File polling has inherent latency (10ms per poll)
- Not truly event-driven (still polling-based)

**Future Evolution** (see Section 8):
- Replace with Unix socketpair for true bidirectional communication
- Event-driven with async I/O
- Streaming trace output instead of file polling

### 3.4. Continuous Trace Reading

**Problem**: Originally used fixed delays after packet injection (200ms) to allow trace writing to complete.

**Solution**: Continuous trace file monitoring with timeout-based completion detection.

**Implementation for Guest-Originated Packets**:
```rust
// Poll trace.log continuously for up to 2 seconds
let search_timeout = Duration::from_secs(2);
let search_start = std::time::Instant::now();
let mut packet_found = false;
let mut packet_found_at: Option<std::time::Instant> = None;

while search_start.elapsed() < search_timeout {
    // Read new lines from trace file
    // ... buffered reading logic ...

    // Quick check if packet IPs are present
    if !packet_found && new_lines.contains(&packet.source_ip) &&
       new_lines.contains(&packet.dest_ip) {
        packet_found = true;
        packet_found_at = Some(std::time::Instant::now());
    }

    // After finding packet, read for another 100ms to capture all trace lines
    // (each packet generates multiple trace lines: packet + rules + verdict)
    if let Some(found_at) = packet_found_at {
        if found_at.elapsed() > Duration::from_millis(100) {
            break;
        }
    }

    tokio::time::sleep(Duration::from_millis(10)).await;
}
```

**Implementation for Host-Originated Packets**:
```rust
// Read trace for 150ms continuously to capture all lines
let read_duration = Duration::from_millis(150);
let read_start = std::time::Instant::now();

while read_start.elapsed() < read_duration {
    // ... read trace lines ...
    tokio::time::sleep(Duration::from_millis(10)).await;
}
```

**Benefits**:
- **Deterministic**: Tests wait for actual trace data instead of guessing timing
- **Multi-line packet support**: Each packet generates multiple trace lines (packet header + rule evaluations + verdict), continuous reading captures all of them
- **Reduced false failures**: No more timing-dependent test failures
- **Faster in practice**: Often completes before the old fixed delays would expire

**Key Insight**: Each injected packet generates multiple trace lines in sequence:
- Line 1: Packet header with IPs/ports/protocol
- Lines 2-N: Rule evaluations with verdicts
- Last line: Final hook verdict (with `meta mark` if set)

The code must continue reading after finding the packet IPs to capture the verdict lines.

### 3.5. Network Transport Architecture

**Key Design Decision: Unix Socketpair with `fd` Transport**

After discovering that UML's `pcap` transport doesn't work (it requires privileged operations), we implemented a Unix socketpair-based approach:

- **Orchestrator Side**: Creates `UnixStream` socketpairs, keeps one end for packet injection/capture
- **UML Side**: File descriptors are passed via `pre_exec` hook using `dup2()` to position them at FD 3, 4, 5, etc.
- **UML Arguments**: Each interface configured as `vec<N>:transport=fd,fd=<FD>,mac=<MAC>` where MAC is fixed (`00:00:00:00:00:0X`)
- **Packet Format**: Complete Ethernet frames with:
  - 14-byte Ethernet header (destination MAC based on interface index)
  - IPv4 (20 bytes) or IPv6 (40 bytes) header with proper checksums
  - Transport layer with proper pseudo-header checksums
  - All checksums calculated via `pnet_packet` library to ensure connection tracking accepts packets

This approach is fully unprivileged and works reliably for testing nftables rulesets.

### 3.6. Packet Building

Packets are built using the `pnet_packet` library in `build_test_frame()`:

1. **Ethernet Header**: 14 bytes with fixed source MAC (`00:11:22:33:44:55`) and destination MAC based on target interface
2. **IP Header**:
   - **IPv4**: 20 bytes with checksum calculated by pnet_packet
   - **IPv6**: 40 bytes (no header checksum per spec)
   - Auto-detection based on IP address format (contains `:` = IPv6)
3. **Transport Layer** (built by `build_transport_layer()`):
   - **TCP**: Proper pseudo-header checksum via `pnet_packet::tcp`
   - **UDP**: Proper pseudo-header checksum via `pnet_packet::udp`
   - **ICMP/ICMPv6**: Type auto-translation for IPv6 (e.g., type 8 → 128 for echo-request)
   - All protocols support optional payload data

The pseudo-header checksum is critical - without it, connection tracking marks packets as INVALID and drops them. Using `pnet_packet` ensures correct checksums for both IPv4 and IPv6.

### 3.7. Bootstrap Process

- **`commands/bootstrap.rs`**: Creates the base UML root filesystem image.
  1. Requires root privileges (checked via `geteuid()`).
  2. Creates a 2GB ext4 filesystem image using `dd` and `mkfs.ext4`.
  3. Mounts the image and runs `debootstrap` to install Debian Bookworm.
  4. Creates `/mnt/host` directory for hostfs mounting.
  5. Installs static `/sbin/init.sh` that mounts hostfs and executes `/mnt/host/run-sim.sh`.
  6. Changes ownership back to the original user via `SUDO_USER` environment variable.

### 3.8. Output Modes

**Normal Mode** (default):

- Clean output showing only test names and PASS/FAIL status
- Test summary with counts
- No UML boot messages or debug output

**Verbose Mode** (`--verbose`):

- Shows UML boot output
- Displays packet injection details
- Shows byte counts and responses
- Full staging directory paths

**Trace Mode** (`--trace`):

- Enables nftables trace capture
- Shows detailed rule evaluation for each packet
- Displays which rules matched and their verdicts
- Useful for debugging firewall behavior

## 4. Current Implementation Status

### Working Features

- ✅ Bootstrap command creates UML rootfs
- ✅ Test command runs simulations
- ✅ Unix socketpair-based networking
- ✅ Proper TCP/IP packet building with checksums
- ✅ Connection tracking functioning correctly
- ✅ Dynamic startup script generation
- ✅ Clean shutdown via signal file
- ✅ Conditional trace and logging (via `--trace` flag)
- ✅ Verbose output mode (via `--verbose` flag)
- ✅ Comprehensive test suite in config.toml
- ✅ **Packet capture from all interfaces** - Orchestrator monitors all sockets for forwarded packets
- ✅ **nft trace integration** - Always enabled internally for verdict detection (shown to user only with --trace)
- ✅ **Hybrid verdict validation** - Uses both nft trace (authoritative) and socket capture (forwarding interface)
- ✅ **Socket buffer draining** - Clears boot messages before test execution
- ✅ **Per-step validation** - Each packet step can have its own expectations
- ✅ **Interface-specific forwarding** - Validates packets are forwarded to correct interface
- ✅ **Trace verdict extraction** - Parses nft monitor output to determine drop/accept verdicts

### Implementation Status

The tool is feature-complete with comprehensive protocol support and test coverage. Key implemented features:

- Hook-aware expectation model (input/forward/output/prerouting/postrouting)
- Hybrid validation using nftables trace + packet capture
- Full protocol support: TCP, UDP, ICMP, IPv6
- NAT validation (SNAT, DNAT, masquerade)
- Advanced nftables features (sets, maps, counters, quotas, rate limiting)
- Multi-zone firewall testing (DMZ configurations)
- Guest-originated packet injection (OUTPUT hook)
- Continuous trace reading (event-driven, no fixed delays)
- 26 comprehensive test suites with 321 test cases

See [CONTRIBUTING.md](CONTRIBUTING.md) for complete test suite listing and [ROADMAP.md](ROADMAP.md) for known limitations.

## 5. Dependencies

Minimal dependency set for fast builds:

- `anyhow`: Error handling
- `clap`: CLI argument parsing
- `libc`: Low-level Unix operations (dup2)
- `nix`: Unix user ID checking (geteuid)
- `pnet_packet`: Packet building and checksums (IPv4/IPv6 support)
- `serde`: TOML deserialization
- `tempfile`: Temporary directory management
- `tokio`: Async runtime for process management
- `toml`: TOML parsing

Minimal codebase with fast compile times and small binary footprint.

## 6. Test Results

### Test Coverage Highlights

- **Connection Tracking**: TCP 3-way handshake, FIN/RST teardown, connection reuse, concurrent connections
- **NAT/Masquerade**: SNAT with explicit IP, masquerade, DNAT port forwarding, bidirectional NAT, SNAT persistence, port range DNAT
- **Multi-Protocol**: TCP, UDP, ICMP tested across all scenarios
- **Protocol Transitions**: Rapid protocol switching, same 5-tuple different protocols, mixed concurrent traffic
- **Port Ranges**: Low privileged ports (500), standard ephemeral (32768), high ports (65535)
- **Concurrent Connections**: Multiple simultaneous connections from same source, multiple sources to same destination
- **High Volume**: Stress testing with 10+ sequential connections, 20+ hosts to single destination, 50+ total connections
- **Rate Limiting**: Baseline tests verifying first packets pass through rate limits
- **Security**: Interface-based filtering, invalid packet handling, policy enforcement, TCP flag validation
- **DMZ/Multi-Zone**: 3-interface firewall with internal/external/DMZ zones, zone-based policies
- **Sets & Maps**: IP address sets, port sets, interval sets (IP ranges), DNAT maps
- **Counters/Quotas**: Named counters for traffic accounting, quota enforcement
- **TCP Flags**: Valid SYN, invalid combinations (FIN+SYN, SYN+RST), NULL scan, XMAS scan (FIN+PSH+URG)
- **ICMP Types**: Echo-request/reply, destination-unreachable, time-exceeded, parameter-problem, redirect, router-advertisement
- **Conntrack Edge Cases**: State persistence across tests, pollution testing, connection reuse validation
- **TTL Validation**: Minimum/maximum TTL, valid ranges
- **Real-World Scenarios**: Mixed traffic, concurrent connections, established state persistence, multi-zone routing

## 7. Testing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on:
- Running individual and multiple test suites
- Test suite organization by feature area
- Debugging with verbose/trace/keep-temp flags
- Creating custom tests

For known limitations and planned improvements, see [ROADMAP.md](ROADMAP.md).
