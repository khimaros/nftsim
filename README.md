# nftsim - nftables Simulation and Testing Tool

A high-fidelity, unprivileged simulation environment for testing nftables firewall rulesets.

## Features

- **Unprivileged Testing**: Runs User-Mode Linux (UML) without requiring root privileges for tests
- **Comprehensive Protocol Support**: TCP, UDP, ICMP, IPv6 with payload data, proper checksums, and connection tracking
- **NAT Validation**: SNAT, DNAT, masquerade with automatic verification
- **Multi-Zone Firewalls**: Support for DMZ/3+ interface configurations
- **Advanced nftables Features**: Sets, maps, counters, quotas, rate limiting
- **Hybrid Validation**: Combines nftables trace output with packet capture for authoritative results
- **Real-World Scenarios**: Docker hosts, VPN gateways, laptop firewalls with comprehensive test coverage
- **321 Test Cases**: Across 26 comprehensive test suites

## Quick Start

### Prerequisites

- Rust toolchain (1.70+)
- Linux kernel source (Debian: `apt-get install linux-source`)
- Build tools: `debootstrap`, `make`, `gcc`, `flex`, `bison`, `bc`
- Sudo access for bootstrap (mount, debootstrap operations)

### Building

```bash
cargo build --release
```

### Bootstrap (One-Time Setup)

Build the custom UML kernel and create rootfs:

```bash
./target/release/nftsim bootstrap

# Or install and run from anywhere
cargo install --path .
nftsim bootstrap
```

**What this does:**
- Builds a custom UML kernel with all nftables features built-in (no modules)
- Creates a 2GB Debian bookworm rootfs with required packages
- Stores all artifacts in `$HOME/.local/share/nftsim/` (relocatable, not tied to source directory)
- Caches kernel build in `$HOME/.local/share/nftsim/linux/` for fast incremental rebuilds
- Caches debootstrap packages in `$HOME/.local/share/nftsim/rootfs-cache/` for fast rootfs recreation
- Prompts for sudo only when needed (mount, debootstrap)

**Outputs:**
- `$HOME/.local/share/nftsim/linux/linux` - Custom UML kernel binary
- `$HOME/.local/share/nftsim/rootfs.img` - 2GB ext4 root filesystem
- `$HOME/.local/share/nftsim/linux/` - Kernel source build directory with build artifacts
- `$HOME/.local/share/nftsim/rootfs-cache/` - Debootstrap package cache

All build artifacts are stored in `$HOME/.local/share/nftsim/` (user-specific, relocatable).

**Relocatable Binary:**
- Resources (bootstrap.sh, harness.sh, kernel.config) are embedded in the binary
- nftsim can be run from anywhere after `cargo install --path .`
- No need to be in the source directory

**Rebuilding:**
- Kernel only rebuilds if embedded kernel.config changes or binary is missing
- Rootfs creation prompts before overwriting existing image

### Running Tests

#### Single Test Suite

```bash
./target/release/nftsim test testdata/01_basics.nft testdata/01_basics.toml
```

#### All Test Suites

```bash
./test.sh
```

#### Specific Test Suites

```bash
./test.sh 01_basics 08_nat 22_ipv6
```

## Test Coverage

nftsim includes **26 comprehensive test suites** with **321 test cases** covering:
- Core firewall functionality (TCP, UDP, ICMP, IPv6)
- NAT and port forwarding scenarios
- Multi-zone firewalls (DMZ configurations)
- Advanced nftables features (sets, maps, counters, quotas, rate limiting)
- Real-world scenarios (Docker hosts, VPN gateways, laptop firewalls)
- Edge cases and security validation

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete list of test suites and their descriptions.

## Writing Tests

Tests are defined using TOML configuration files. Here's a simple example:

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

# Guest setup
[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# Test case
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

For complete TOML format reference, examples, and best practices, see [TESTDATA.md](TESTDATA.md).

## How It Works

1. **Socketpair Creation**: Unix socketpairs for each network interface
2. **UML Launch**: Spawns User-Mode Linux with `fd` transport
3. **Network Setup**: Configures interfaces, routes, sysctls in guest
4. **Ruleset Loading**: Loads your nftables rules
5. **Trace Enablement**: Enables `meta nftrace set 1` for verdict detection
6. **Packet Injection**: Builds Ethernet/IP/TCP frames with proper checksums
7. **Hybrid Validation**: Combines trace output (verdict) + socket capture (interface)
8. **Result Display**: PASS/FAIL with detailed expectations

## Architecture

- **Orchestrator**: Rust binary (`nftsim`) manages UML, injects packets, validates results
- **UML Guest**: Isolated Linux kernel with your firewall rules
- **Transport**: Unix socketpairs with `fd` transport (fully unprivileged)
- **Validation**: Hybrid approach using nftables trace + packet capture

See [DESIGN.md](DESIGN.md) for detailed architecture documentation.

For known limitations and planned improvements, see [ROADMAP.md](ROADMAP.md).

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development workflow and debugging tips
- How to create custom tests
- Code structure and key implementation details
- Performance metrics and test output modes

For architectural details, see [DESIGN.md](DESIGN.md).
