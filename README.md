# nftsim - nftables simulation and testing tool

an unprivileged simulation environment for testing nftables firewall rulesets inside User-Mode Linux (UML).

## features

- **unprivileged testing**: runs a real Linux kernel in UML without root
- **protocol support**: TCP, UDP, ICMP and IPv6 with payloads, valid checksums and connection tracking
- **NAT validation**: checks SNAT, DNAT and masquerade (masquerade addresses are read from the guest's conntrack table)
- **multi-zone and dual-stack**: supports arbitrary interfaces and multiple IPv4/IPv6 addresses per interface
- **nftables coverage**: sets, maps, counters, quotas, rate limiting and custom chain names (resolved to hooks via `chains.json`)
- **trace-based validation**: verdicts, output interfaces and NAT come directly from `nft monitor trace`
- **fail-closed instrumentation**: aborts if the guest never signals `READY`, the trace monitor dies, or trace output contains unrecognized lines

## quick start

### prerequisites

- Rust toolchain (1.70+)
- Linux kernel source (Debian: `apt-get install linux-source`)
- build tools: `debootstrap`, `make`, `gcc`, `flex`, `bison`, `bc`
- sudo access for one-time bootstrap (loop mount and `debootstrap`)

### build and bootstrap

```bash
make                        # builds ./target/release/nftsim
./target/release/nftsim bootstrap
```

bootstrap creates `$HOME/.local/share/nftsim/` (independent of the checkout) containing:
- `linux/linux` - custom UML kernel with all required netfilter features built in
- `linux/` - cached kernel build tree (rebuilt only when `res/kernel.config` changes)
- `rootfs.img` - 2GB Debian bookworm root filesystem
- `rootfs-cache/` - cached `debootstrap` packages

test runs never write to `rootfs.img`: each run attaches a throwaway copy-on-write overlay (`rootfs.cow`), so concurrent runs share one image. resources (`bootstrap.sh`, `harness.sh`, `kernel.config`) are embedded in the binary, so `cargo install --path .` runs from anywhere.

### running tests

```bash
# single suite with explicit ruleset
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml

# self-contained suite (sets `ruleset = "..."` in the TOML file)
./target/release/nftsim test path/to/suite.toml

# ruleset with embedded `# !` test directives
./target/release/nftsim test testdata/27_gateway_embedded.nft

# all 26 test suites (321 test cases) or a subset
./test.sh
./test.sh 01_basics 08_nat 22_ipv6
```

`nftsim test` exits non-zero when any test case fails or the test harness encounters an error. pass `--report <path>` for JSON results:

```json
{
  "total": 8, "passed": 7, "failed": 1,
  "suites": [{
    "config": "suite.toml", "ruleset": "nftables.conf",
    "tests": [{ "name": "...", "passed": false,
                "reason": "step 1: verdict: accept (expected drop) at PREROUTING hook ..." }]
  }]
}
```

## writing a test

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
]
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

[[tests]]
name = "allow HTTP from internal to external"

[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

see [TESTDATA.md](TESTDATA.md) for the full TOML reference.

## documentation

- [TESTDATA.md](TESTDATA.md) - TOML test format reference
- [DESIGN.md](DESIGN.md) - architecture and implementation details
- [CONTRIBUTING.md](CONTRIBUTING.md) - development workflow, test suites and pitfalls
- [ROADMAP.md](ROADMAP.md) - known limitations and planned work

## license

see [LICENSE](LICENSE).
