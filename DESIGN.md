# nftsim architecture and design

technical blueprint of `nftsim`. for the TOML test format see [TESTDATA.md](TESTDATA.md); for development commands see [CONTRIBUTING.md](CONTRIBUTING.md).

## 1. workflow

1. parse `TestArgs` (`src/cli.rs`) and each TOML `SimConfig` (`src/config.rs`), or `# !` directives from a ruleset (`src/commands/test/embedded.rs`).
2. stage a temporary directory mounted into the guest via UML `hostfs` at `/mnt/host`, containing `rules.nft`, generated `entrypoint.sh`, embedded `harness.sh`, optional `pre-nft-commands.sh` / `post-nft-commands.sh`, and empty control channel files.
3. create one Unix socketpair (`UnixStream::pair()`) per configured interface (`src/commands/test/setup.rs`).
4. spawn UML with a per-run copy-on-write disk overlay (`ubd0=<tmpdir>/rootfs.cow,<rootfs.img>`) and `vec<N>:transport=fd,fd=<FD>,mac=<MAC>` arguments, using `pre_exec` + `dup2()` to place the sockets at FDs `3, 4, ...`.
5. `/sbin/init.sh` mounts `/proc`, `/sys` and `/mnt/host`, then execs `entrypoint.sh`, which renames `vec*` interfaces, assigns addresses (with `nodad` for IPv6), applies sysctls and routes, and execs `harness.sh`.
6. `harness.sh` runs `pre-nft-commands.sh`, loads `rules.nft`, dumps base chain hooks to `chains.json`, inserts `meta nftrace set 1` at the start of every chain in every table, starts `nft monitor trace`, waits for netlink trace subscription, runs `post-nft-commands.sh`, starts the command listener, and writes `READY`.
7. `runner.rs` waits for `READY`, opens `chains.json` and `trace.log`, drains boot frames from the sockets, and executes every packet step (host frame injection or guest `EXEC` command).
8. after the last step, `runner.rs` sends `SHUTDOWN`, checks that the trace monitor stayed alive and every trace line matches the expected format, waits for UML to halt, and reports results (and optional JSON `--report`).

## 2. module layout

- `src/cli.rs` - CLI definitions (`bootstrap`, `test`)
- `src/config.rs` - TOML schema structs, lowercase `Verdict` deserializer, address helpers
- `src/resources.rs` - compile-time embedded `res/{bootstrap.sh,harness.sh,kernel.config}` and `$HOME/.local/share/nftsim/` path resolution
- `src/commands/bootstrap.rs` - runs embedded `bootstrap.sh` to build the UML kernel and Debian bookworm rootfs
- `src/commands/test/runner.rs` - UML lifecycle, control channel, per-step trace collection, orchestration
- `src/commands/test/setup.rs` - `entrypoint.sh` generation and socketpair creation
- `src/commands/test/packet.rs` - Ethernet/IPv4/IPv6/TCP/UDP/ICMP frame construction via `pnet_packet`
- `src/commands/test/guest.rs` - detects guest-originated packets (`source_ip` matches any interface address) and builds `socat`/`ping` commands
- `src/commands/test/trace.rs` - `chains.json` hook map, `nft monitor trace` envelope validation, per-packet verdict/oif/NAT extraction, `/proc/net/nf_conntrack` masquerade lookup
- `src/commands/test/validation.rs` - compares `TraceInfo` against `PacketStep` expectations
- `src/commands/test/report.rs` - JSON report serialization (`--report`)
- `src/commands/test/embedded.rs` - parses `# !` directives embedded in rulesets

## 3. key mechanisms

### 3.1. unprivileged network transport and packet building

UML's `fd` vector transport uses Unix socketpairs instead of privileged `pcap`/tap devices. each interface gets a fixed MAC (`00:00:00:00:00:01`, `02`, ...) so `build_test_frame()` can address injected frames directly. `pnet_packet` computes IPv4 header and TCP/UDP/ICMP pseudo-header checksums so conntrack does not drop packets as `INVALID`. for IPv6, ICMPv4 types `8`/`0` are translated to ICMPv6 `128`/`129`.

### 3.2. shared rootfs with copy-on-write overlays

UML attaches `ubd0=<tmpdir>/rootfs.cow,<rootfs.img>`, opening the shared `rootfs.img` read-only with a shared lock and directing guest writes to the throwaway sparse overlay. this prevents concurrent `nftsim test` runs from panicking on an exclusive lock.

### 3.3. file-based control channel

host and guest exchange newline-delimited messages through append-only files on `/mnt/host`:
- `host_to_guest.txt`: `EXEC <command>`, `SHUTDOWN`
- `guest_to_host.txt`: `READY`, `ACK <exit_code>`

`harness.sh` polls `host_to_guest.txt` every 10ms using line-number tracking (`sed -n "${line_num}p"` and parameter expansion, avoiding subshell scope loss). `send_guest_message()` in `runner.rs` counts `ACK` lines so each request waits for its own reply. [ROADMAP.md](ROADMAP.md) tracks migrating this channel to a Unix socketpair.

### 3.4. trace collection and instrument integrity

trace output is the single source of truth for verdicts, output interfaces and NAT:

- **per-step slicing**: before injecting a packet, `runner.rs` drains idle guest traffic into `accumulated_trace` and records the byte offset. `collect_packet_trace()` polls `trace.log` every 10ms until `parse_trace_for_packet()` matches inside that step's slice, then reads until quiet for 150ms (`TRACE_QUIET_MS`) or times out after 3s (`TRACE_SEARCH_TIMEOUT_MS`). searching only the current step's slice prevents repeated 5-tuples from matching stale traces.
- **hard readiness checks**: `harness.sh` starts `nft monitor trace` in append mode (`>>`) with stderr redirected to `trace_monitor.err`, polls `/proc/net/netlink` (up to 2s) for a `NETLINK_NETFILTER` socket in `NFNLGRP_NFTRACE` (`0x100`), and exits non-zero if it never subscribes. `runner.rs` fails immediately if `READY` times out (`READY_TIMEOUT_SECS`), `chains.json` cannot be read, or `trace.log` is missing.
- **monitor liveness**: on `SHUTDOWN`, `harness.sh` verifies `kill -0 "$TRACE_PID"` and `trace_subscribed` before replying `ACK 0`; a dead or unsubscribed monitor replies `ACK 1` and fails the simulation with any stderr from `trace_monitor.err`.
- **trace envelope validation**: after all steps complete, `find_unrecognized_trace_lines()` checks every non-empty line in `trace.log` against the `nft monitor trace` envelope (`trace id <hex> <family> <table> <chain> (packet: ... | rule ... (verdict ...) | verdict ... | policy ...)`). any unrecognized line fails the run so upstream `nft` output changes cannot quietly produce wrong verdicts.
- **hook resolution**: `chains.json` (`nft -j list chains`) maps `family table chain` to its base hook so chains named for their owner (e.g. `preraw`, `DOCKER`) report verdicts under their hook.
- **NAT and masquerade**: `trace.rs` parses `snat`/`dnat` (`to`, `ip to`, `ip6 to`, bare or `[ipv6]:port`) and flags `masquerade` rules. because masquerade traces omit the chosen address, `runner.rs` dumps `/proc/net/nf_conntrack` from the guest and reads the reply tuple's destination address, falling back to the output interface's first configured address of the packet's family. NAT addresses are compared by parsed value.
- **fail-fast coordination**: `runner.rs` uses `tokio::select!` across the injector task, UML child exit and overall `--timeout` deadline. any infrastructure error kills UML immediately and preserves the temp directory with all logs.

## 4. output modes

- **default**: per-case pass/fail lines and summary counts
- **`--verbose`**: boot progress, socket drains, injection details and per-expectation diagnostics (always written to `test.log`)
- **`--trace`**: streams `nft monitor trace` output to stdout
- **`--keep-temp`**: preserves the staging directory after passing runs (failed infrastructure runs preserve it automatically)
- **`--report <path>`**: writes structured JSON results

## 5. dependencies

`anyhow`, `clap`, `libc`, `nix`, `pnet_packet`, `serde`, `serde_json`, `tempfile`, `tokio`, `toml`.
