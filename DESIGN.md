# nftsim architecture and design

the design and architecture of `nftsim`, used as the technical blueprint for development.

## 1. core principles and workflow

`nftsim` is a command-line tool that provides a high-fidelity, unprivileged and observable simulation environment for nftables rulesets.

the core workflow:

1.  the user runs `nftsim test <RULESET_PATH> <CONFIG_TOML_1> [CONFIG_TOML_2...] [--trace] [--verbose]`.
2.  for each config file, the tool parses the test definition: the virtual network topology, kernel parameters and a series of stateful test sequences.
3.  it prepares a temporary staging directory for the run.
4.  it generates a startup script (`entrypoint.sh`) from the network and guest setup configuration.
5.  it creates a Unix socketpair for each network interface for unprivileged packet injection.
6.  it launches a User-Mode Linux (UML) kernel with the `fd` transport for network interfaces.
7.  the guest boots and runs the startup script, which configures networking and sysctls, loads the nftables ruleset and enables trace monitoring.
8.  the orchestrator injects test packets through the Unix sockets as Ethernet/IP/TCP frames with valid checksums.
9.  the firewall processes packets with full connection tracking.
10. nftables trace data records rule evaluation and verdicts; `--trace` also shows it to the user.
11. after all tests complete, each test case is reported as pass or fail.

## 2. test definition (`config.toml`)

### 2.1. expectation model

the expectation model uses **nftables concepts** directly:

- **hook-based**: tests name the nftables hook that processes the packet (input, forward, output, etc.)
- **real verdicts**: nftables verdicts (accept, drop, reject) rather than synthetic ones
- **separation of concerns**: the verdict (what nftables decides) is separate from routing (where the packet goes)
- **interface validation**: `to_interface` validates forwarding independently of the verdict
- **NAT validation**: `src_nat` and `dst_nat` check address translation

```toml
# packet accepted at the forward hook, exits on eth1
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# packet accepted at the input hook (delivered locally)
expect = [ { hook = "input", verdict = "accept" } ]

# NAT validation
expect = [ { hook = "postrouting", verdict = "accept", src_nat = "10.0.0.1" } ]
```

### 2.2. TOML structure

to keep simulations repeatable and self-contained, the whole test environment is defined in a single TOML file. the tool accepts several such files to run a suite.

the file has three sections: `[network]` for topology, `[guest_setup]` for kernel and command configuration, and an array of `[[tests]]` for the packet sequences. each test defines its packet steps with `[[tests.packets]]` table arrays, which read better than inline arrays for multi-packet scenarios.

```toml
# config.toml

# network topology for the UML guest.
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
]

# static routes for the guest.
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

# setup procedure for the guest environment.
[guest_setup]
# sysctl key-value pairs to set.
sysctls = { "net.ipv4.ip_forward" = "1" }

# shell commands to run after networking is up, but BEFORE the nftables ruleset is loaded.
pre_nft_commands = [
  "echo 'Loading conntrack...'",
  "modprobe nf_conntrack || echo 'conntrack may be built-in'"
]

# shell commands to run AFTER the nftables ruleset is loaded.
post_nft_commands = [
  "echo '=== Loaded nftables ruleset ==='",
  "nft list ruleset"
]


# test cases. each test case is a sequence of packet steps.
[[tests]]
name = "Allowed HTTP Connection from Internal"

# each packet step is defined using [[tests.packets]]
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

### 2.3. implementation in Rust

- **`src/config.rs`**: the Rust structs (`SimConfig`, `Network`, `GuestSetup`, `TestCase`, `PacketStep`, etc.) that mirror the TOML structure. they derive `serde::Deserialize`.
- **`clap`**: the `test` command in `src/cli.rs` takes one positional argument for the ruleset, any number of positional config files, and optional `--trace` and `--verbose` flags.
- **lowercase verdicts**: the `Verdict` enum (`Accept`, `Drop`, `Reject`) deserializes through a custom function that accepts only lowercase strings, enforcing the convention.
- **expectation validation**: the `expect` field uses nftables verdicts with hook awareness:
  - **verdict types**: `accept`, `drop`, `reject`
  - **hook field**: the nftables hook (input, forward, output, prerouting, postrouting)
  - **interface validation**: `to_interface` is the expected output interface for forwarded packets, checked against the trace `oif`
  - **NAT validation**: `src_nat` and `dst_nat` validate SNAT/DNAT/masquerade address translation
    - parses trace output for `snat to`, `snat ip to`, `dnat to`, `dnat ip to` and `masquerade`
    - for masquerade, the trace carries no address, so the runner has the guest dump `/proc/net/nf_conntrack` and takes the reply tuple's destination for the packet's connection: the address the kernel chose. if no entry is found it falls back to the output interface's first configured address of the packet's family
    - NAT addresses are compared by value, so any spelling of an IPv6 address matches

## 3. component breakdown

### 3.1. the Rust orchestrator (`nftsim`)

- **`src/commands/test/`**: the simulation logic.
  1.  **parsing**: reads each config file into a `SimConfig` struct.
  2.  **guest script**: runs the standalone `harness.sh` with dynamic chain discovery and trace rule insertion.
  3.  **socketpairs**: creates a Unix socketpair per network interface with `UnixStream::pair()`.
  4.  **UML launch**: spawns UML with `vec<N>:transport=fd,fd=<FD>,mac=<MAC>` arguments, using `pre_exec` to dup2 the socket file descriptors. the root disk is `ubd0=<tmpdir>/rootfs.cow,<rootfs.img>`: guest writes land in a sparse per-run copy-on-write overlay, so UML opens the shared image read-only under a shared lock and several runs can share one image. attached `rw` directly, UML takes an exclusive lock and the second run panics at boot.
  5.  **trace enablement**: harness.sh discovers all chains, inserts `meta nftrace set 1` at position 0 and starts `nft monitor trace`.
  6.  **packet injection**: builds complete Ethernet frames with pnet_packet (IPv4/IPv6) and writes them to the Unix sockets.
  7.  **trace parsing**: reads trace.log and extracts per-hook verdicts by matching packet IPs/ports, with a fallback for conntrack de-NAT.
  8.  **trace-only validation**: the nftables trace is the single source of truth, which avoids socket capture timing dependencies.
  9.  **per-hook verdicts**: validates specific hooks in the packet's path (PREROUTING -> FORWARD -> POSTROUTING). traces name the chain, so each base chain is resolved to its hook through `chains.json`; a chain missing from it (or no `chains.json`) falls back to its own name.
  10. **NAT validation**: extracts SNAT/DNAT from the trace and reads the masquerade address from the guest's conntrack table, falling back to an address of the output interface (packet line oif, then the rule line oifname).
  11. **logging**: always writes verbose logs to test.log and trace.log, captures UML stdout/stderr, and keeps them with `--keep-temp`.
  12. **results**: prints pass/fail per test case. `--trace` also prints the full trace log, and `--report` writes JSON results (`report.rs`).

### 3.2. the UML guest environment

- **standalone script (`harness.sh`)**: runs inside the guest for environment setup.
  1.  run `pre_nft_commands` if present.
  2.  load the user's ruleset (`nft -f /mnt/host/rules.nft`), then record each base chain's hook with `nft -j list chains > /mnt/host/chains.json`, since real rulesets name chains for their owner (wg-quick's `preraw`, docker's `DOCKER`) rather than their hook.
  3.  **chain discovery**: parse `nft list tables` output to find all tables and chains.
  4.  **trace rule insertion**: insert `meta nftrace set 1` at position 0 in EVERY discovered chain, whatever its name.
  5.  start `nft monitor trace > /mnt/host/trace.log &` and wait until it has subscribed (see 3.4).
  6.  run `post_nft_commands` if present.
  7.  **message loop**: poll `host_to_guest.txt` for EXEC and SHUTDOWN messages.
  8.  kill the trace monitor and sync before halt.

- **startup script (`entrypoint.sh`)**: generated by Rust, configures the guest.
  1.  mount `/proc`, `/sys` and hostfs at `/mnt/host`.
  2.  rename vector interfaces from `vec0`, `vec1`, etc. to their configured names (`eth0`, `eth1`).
  3.  configure interface addresses (`ip addr add`, `ip link set up`).
  4.  set `sysctl` values.
  5.  configure routes (`ip route add`).
  6.  run `harness.sh` for nftables setup and trace enablement.
  7.  sync and halt with `halt -f`.

### 3.3. control channel and message protocol

the host and guest communicate through append-only message files:
- `host_to_guest.txt`: commands from orchestrator to guest (EXEC, SHUTDOWN)
- `guest_to_host.txt`: responses from guest to orchestrator (READY, ACK)

each message is one newline-terminated line; the first word is the message type and the rest is the payload (`TYPE payload data here\n`).

**host -> guest messages**:
```
EXEC <command>     # execute shell command in guest
SHUTDOWN           # request graceful shutdown
```

**guest -> host messages**:
```
READY              # guest boot complete, ready for commands
ACK <exit_code>    # command execution completed with exit code
```

guest message listener (in `harness.sh`, simplified):
```bash
# track last read line number to avoid re-processing
last_line=0
shutdown_received=0

while [ "$shutdown_received" -eq 0 ]; do
  if [ -f /mnt/host/host_to_guest.txt ]; then
    current_lines=$(wc -l < /mnt/host/host_to_guest.txt)

    if [ "$current_lines" -gt "$last_line" ]; then
      # process each new line using sed (avoids subshell issues)
      line_num=$((last_line + 1))
      while [ "$line_num" -le "$current_lines" ]; do
        line=$(sed -n "${line_num}p" /mnt/host/host_to_guest.txt)

        # split on first space
        msg_type="${line%% *}"
        msg_data="${line#* }"

        case "$msg_type" in
          EXEC)
            eval "$msg_data" >> /mnt/host/commands.log 2>&1
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

  sleep 0.01  # fast polling - 10ms
done
```

host message sending (in `runner.rs`):
```rust
// append EXEC message
let message = format!("EXEC {}\n", cmd);
std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(&host_to_guest_path)?
    .write_all(message.as_bytes())?;

// wait for ACK response by counting ACK lines in guest_to_host.txt
```

append-only files are easy to follow with `tail -f`, keep message order, and need no synchronization primitives beyond line counting. the cost is polling latency (10ms per poll); [ROADMAP.md](ROADMAP.md) tracks moving to an event-driven channel.

### 3.4. continuous trace reading

**problem**: fixed read windows after injection (150ms for host packets) lose trace lines whenever the host is loaded: the lines reach `trace.log` late, and the step fails with "packet not found" or a partial hook list.

**solution**: `collect_packet_trace()` in `runner.rs` serves both injection paths. it polls `trace.log` every 10ms until `parse_trace_for_packet()` matches the packet in the lines read since injection, then keeps reading until no new lines have arrived for 150ms (`TRACE_QUIET_MS`). a packet that never shows up gives up after 3s (`TRACE_SEARCH_TIMEOUT_MS`). on an idle host a step costs about the same as the old fixed window.

**monitor readiness**: `nft monitor trace` subscribes to the trace netlink group asynchronously, and packets that arrive before it joins are never traced. `harness.sh` holds READY until `/proc/net/netlink` shows a `NETLINK_NETFILTER` socket in the `NFNLGRP_NFTRACE` group (up to 2s, logged to `harness.log`).

each injected packet generates several trace lines in sequence:
- line 1: packet header with IPs/ports/protocol
- lines 2-N: rule evaluations with verdicts
- last line: final hook verdict (with `meta mark` if set)

so the reader must continue past the line with the packet IPs to capture the verdict lines.

### 3.5. network transport

**design decision: Unix socketpair with the `fd` transport**

UML's `pcap` transport requires privileged operations, so nftsim uses Unix socketpairs:

- **orchestrator side**: creates `UnixStream` socketpairs and keeps one end for packet injection/capture
- **UML side**: file descriptors are passed through a `pre_exec` hook with `dup2()` to place them at FD 3, 4, 5, etc.
- **UML arguments**: each interface is `vec<N>:transport=fd,fd=<FD>,mac=<MAC>` with a fixed MAC (`00:00:00:00:00:0X`)
- **packet format**: complete Ethernet frames with:
  - a 14-byte Ethernet header (destination MAC from the interface index)
  - an IPv4 (20 bytes) or IPv6 (40 bytes) header with correct checksums
  - a transport layer with pseudo-header checksums
  - all checksums calculated by `pnet_packet` so connection tracking accepts the packets

this approach is fully unprivileged.

### 3.6. packet building

`build_test_frame()` builds packets with `pnet_packet`:

1. **Ethernet header**: 14 bytes with a fixed source MAC (`00:11:22:33:44:55`) and a destination MAC from the target interface
2. **IP header**:
   - **IPv4**: 20 bytes with checksum calculated by pnet_packet
   - **IPv6**: 40 bytes (no header checksum per spec)
   - detected from the address format (contains `:` = IPv6)
3. **transport layer** (`build_transport_layer()`):
   - **TCP**: pseudo-header checksum via `pnet_packet::tcp`
   - **UDP**: pseudo-header checksum via `pnet_packet::udp`
   - **ICMP/ICMPv6**: type translation for IPv6 (e.g., type 8 -> 128 for echo-request)
   - every protocol supports optional payload data

without a correct pseudo-header checksum, connection tracking marks packets INVALID and drops them.

### 3.7. bootstrap process

- **`src/commands/bootstrap.rs`**: writes the embedded `bootstrap.sh` and `kernel.config` to a temp directory and runs the script as the regular user. the script:
  1. checks for required commands and uses sudo only for privileged steps (mount, debootstrap).
  2. builds the UML kernel in `$HOME/.local/share/nftsim/linux/`, only when the config is newer than the binary or the binary is missing.
  3. creates a 2GB ext4 image with `dd` and `mkfs.ext4`.
  4. loop-mounts the image and runs `debootstrap` to install Debian bookworm.
  5. creates the `/mnt/host` directory for hostfs.
  6. installs a static `/sbin/init.sh` that mounts hostfs and runs `/mnt/host/entrypoint.sh`.

### 3.8. output modes

- **normal** (default): test names with pass/fail and a summary with counts; UML boot messages and debug output are hidden
- **verbose** (`--verbose`): UML boot output, packet injection details, byte counts and staging directory paths
- **trace** (`--trace`): the nftables trace for each packet, showing which rules matched and their verdicts

## 4. implementation status

implemented:

- hook-aware expectation model (input/forward/output/prerouting/postrouting)
- per-step expectations and trace-based validation of verdicts, output interfaces and NAT
- protocol support: TCP, UDP, ICMP, IPv6
- NAT validation (SNAT, DNAT, masquerade)
- sets, maps, counters, quotas and rate limiting
- multi-zone firewall testing (DMZ configurations)
- guest-originated packet injection (OUTPUT hook)
- continuous trace reading (no fixed read windows)
- shared rootfs image with per-run copy-on-write overlays
- JSON results with `--report`
- 26 test suites with 321 test cases

see [CONTRIBUTING.md](CONTRIBUTING.md) for the test suite listing and [ROADMAP.md](ROADMAP.md) for known limitations.

## 5. dependencies

a small dependency set for fast builds and a small binary:

- `anyhow`: error handling
- `clap`: CLI argument parsing
- `libc`: low-level Unix operations (dup2)
- `nix`: Unix helpers
- `pnet_packet`: packet building and checksums (IPv4/IPv6)
- `serde`: TOML deserialization
- `serde_json`: `chains.json` parsing and `--report` output
- `tempfile`: temporary directory management
- `tokio`: async runtime for process management
- `toml`: TOML parsing

## 6. test coverage

- **connection tracking**: TCP 3-way handshake, FIN/RST teardown, connection reuse, concurrent connections
- **NAT/masquerade**: SNAT with explicit address, masquerade, DNAT port forwarding, bidirectional NAT, SNAT persistence, port range DNAT
- **multi-protocol**: TCP, UDP and ICMP across all scenarios
- **protocol transitions**: rapid protocol switching, same 5-tuple with different protocols, mixed concurrent traffic
- **port ranges**: low privileged ports (500), standard ephemeral (32768), high ports (65535)
- **concurrent connections**: several simultaneous connections from one source, several sources to one destination
- **high volume**: 10+ sequential connections, 20+ hosts to a single destination, 50+ total connections
- **rate limiting**: baseline tests verifying the first packets pass through rate limits
- **security**: interface-based filtering, invalid packet handling, policy enforcement, TCP flag validation
- **DMZ/multi-zone**: 3-interface firewall with internal/external/DMZ zones and zone-based policies
- **sets and maps**: address sets, port sets, interval sets (address ranges), DNAT maps
- **counters/quotas**: named counters for traffic accounting, quota enforcement
- **TCP flags**: valid SYN, invalid combinations (FIN+SYN, SYN+RST), NULL scan, XMAS scan (FIN+PSH+URG)
- **ICMP types**: echo-request/reply, destination-unreachable, time-exceeded, parameter-problem, redirect, router-advertisement
- **conntrack edge cases**: state persistence across tests, pollution testing, connection reuse
- **TTL validation**: minimum/maximum TTL, valid ranges
- **real-world scenarios**: Docker hosts, VPN gateways, laptop firewalls, multi-zone routing

see [CONTRIBUTING.md](CONTRIBUTING.md) for running suites, debugging with `--verbose`/`--trace`/`--keep-temp` and creating custom tests.
