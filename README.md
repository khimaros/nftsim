# nftsim - nftables simulation and testing tool

an unprivileged, high-fidelity simulation environment for testing nftables firewall rulesets.

## features

- **unprivileged testing**: tests run in User-Mode Linux (UML) without root
- **protocol support**: TCP, UDP, ICMP and IPv6 with payload data, correct checksums and connection tracking
- **NAT validation**: SNAT, DNAT and masquerade are verified automatically
- **multi-zone firewalls**: DMZ and other configurations with three or more interfaces
- **dual-stack hosts**: interfaces can carry several addresses (`ips`), and masquerade is checked against the address the kernel actually chose
- **nftables features**: sets, maps, counters, quotas, rate limiting
- **trace-based validation**: verdicts, output interfaces and NAT come from nftables trace output
- **real-world scenarios**: Docker hosts, VPN gateways and laptop firewalls
- **321 test cases** across 26 test suites

## quick start

### prerequisites

- Rust toolchain (1.70+)
- Linux kernel source (Debian: `apt-get install linux-source`)
- build tools: `debootstrap`, `make`, `gcc`, `flex`, `bison`, `bc`
- sudo access for bootstrap (mount and debootstrap)

### building

```bash
cargo build --release
```

### bootstrap (one-time setup)

build the custom UML kernel and create the rootfs:

```bash
./target/release/nftsim bootstrap

# or install and run from anywhere
cargo install --path .
nftsim bootstrap
```

bootstrap:
- builds a custom UML kernel with every nftables feature built in (no modules)
- creates a 2GB Debian bookworm rootfs with the required packages
- caches the kernel build and debootstrap packages for fast rebuilds
- prompts for sudo only when needed (mount, debootstrap)

all artifacts live in `$HOME/.local/share/nftsim/`, independent of the source directory:
- `linux/linux` - custom UML kernel binary
- `linux/` - kernel source and build directory
- `rootfs.img` - 2GB ext4 root filesystem
- `rootfs-cache/` - debootstrap package cache

the kernel is rebuilt only when the embedded kernel.config changes or the binary is missing. bootstrap prompts before overwriting an existing rootfs.

test runs never write to `rootfs.img`: each run keeps its guest's disk writes in a throwaway copy-on-write overlay, so several `nftsim test` runs can share the image at once.

the resources (bootstrap.sh, harness.sh, kernel.config) are embedded in the binary, so nftsim runs from anywhere after `cargo install --path .`.

### running tests

#### single test suite

```bash
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml
```

a suite that names its ruleset (`ruleset = "..."`, see
[TESTDATA.md](TESTDATA.md)) runs on its own:

```bash
nftsim test path/to/suite.toml
```

`nftsim test` exits non-zero when any test case fails. for wrappers (unittest,
pytest, CI), `--report <path>` writes every case as JSON with the reason each
failure happened:

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

#### all test suites

```bash
./test.sh
```

#### specific test suites

```bash
./test.sh 01_basics 08_nat 22_ipv6
```

## test coverage

the 26 test suites cover:
- core firewall behavior (TCP, UDP, ICMP, IPv6)
- NAT and port forwarding
- multi-zone firewalls (DMZ)
- sets, maps, counters, quotas and rate limiting
- real-world scenarios (Docker hosts, VPN gateways, laptop firewalls)
- edge cases and security checks

see [CONTRIBUTING.md](CONTRIBUTING.md) for the list of suites.

## writing tests

tests are defined in TOML files. a simple example:

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

# guest setup
[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# test case
[[tests]]
name = "Allow HTTP from Internal to External"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] }
}
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" }
]
```

see [TESTDATA.md](TESTDATA.md) for the full TOML format reference and examples.

## how it works

1. **socketpairs**: one Unix socketpair per network interface
2. **UML launch**: User-Mode Linux starts with the `fd` transport
3. **network setup**: interfaces, routes and sysctls are configured in the guest
4. **ruleset loading**: your nftables rules are loaded
5. **tracing**: `meta nftrace set 1` is inserted into every chain
6. **packet injection**: Ethernet/IP/TCP frames are built with correct checksums
7. **validation**: trace output gives the verdict, output interface and NAT for each hook
8. **results**: pass/fail for each test case, with the reason for each failure

## architecture

- **orchestrator**: the Rust binary (`nftsim`) manages UML, injects packets and validates results
- **UML guest**: an isolated Linux kernel running your firewall rules
- **transport**: Unix socketpairs with the `fd` transport (fully unprivileged)

see [DESIGN.md](DESIGN.md) for the architecture and [ROADMAP.md](ROADMAP.md) for known limitations and planned work.

## license

see the LICENSE file.

## contributing

see [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, debugging tips, writing tests and code structure.
