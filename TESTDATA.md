# TOML Test Format Reference

This document describes the TOML configuration format for defining nftsim test cases.

## Table of Contents

- [Overview](#overview)
- [File Structure](#file-structure)
- [Network Configuration](#network-configuration)
- [Guest Setup](#guest-setup)
- [Test Definitions](#test-definitions)
- [Packet Specifications](#packet-specifications)
- [Expectations](#expectations)
- [Complete Examples](#complete-examples)

## Overview

Each test suite consists of two files:
- `testdata/NN_name.nft` - The nftables ruleset to test
- `testdata/NN_name.toml` - Test configuration and test cases

The TOML file defines the network topology, guest environment setup, and test cases with packet specifications and expectations.

## File Structure

A test configuration file has three main sections:

```toml
[network]
# Network topology: interfaces and routes

[guest_setup]
# Guest environment: sysctls, pre/post commands

[[tests]]
# Test cases: packets and expectations
```

## Network Configuration

### Interfaces

Define network interfaces with IP addresses (IPv4 or IPv6):

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
  { name = "eth2", ip = "2001:db8:1::1/64" },  # IPv6
]
```

**Fields:**
- `name` (required): Interface name (e.g., "eth0", "eth1")
- `ip` (required): IP address with CIDR notation (IPv4 or IPv6)

### Routes

Define static routes:

```toml
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },        # IPv4 default route
  { destination = "::/0", via = "2001:db8:2::2" },        # IPv6 default route
  { destination = "192.168.0.0/16", via = "10.0.0.3" },   # Specific network
]
```

**Fields:**
- `destination` (required): Destination network in CIDR notation
- `via` (required): Gateway IP address

## Guest Setup

Configure the UML guest environment:

```toml
[guest_setup]
sysctls = {
  "net.ipv4.ip_forward" = "1",
  "net.ipv6.conf.all.forwarding" = "1",
  "net.ipv4.conf.all.rp_filter" = "0",
}

pre_commands = [
  "ip link set eth0 up",
  "echo 'Custom setup command'",
]

post_commands = [
  "nft list ruleset",
]
```

**Fields:**
- `sysctls` (optional): Key-value pairs of sysctl settings
- `pre_commands` (optional): Shell commands to run before loading nftables rules
- `post_commands` (optional): Shell commands to run after loading nftables rules

## Test Definitions

Tests are defined using TOML table arrays:

```toml
[[tests]]
name = "Test Name"

[[tests.packets]]
packet = { ... }
expect = [ ... ]

[[tests.packets]]
packet = { ... }
expect = [ ... ]
```

**Test fields:**
- `name` (required): Descriptive test name

**Packet fields:**
- `packet` (required): Packet specification (see [Packet Specifications](#packet-specifications))
- `expect` (required): Array of expectations (see [Expectations](#expectations))

## Packet Specifications

All packets must specify:
- `on_interface`: Interface name where packet enters/exits
- `source_ip`: Source IP address (IPv4 or IPv6)
- `dest_ip`: Destination IP address (IPv4 or IPv6)
- Protocol-specific fields: `tcp`, `udp`, or `icmp`

### TCP Packets

```toml
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = {
    source_port = 40000,           # Numeric port
    dest_port = "http",            # Or named port ("http", "https", "ssh", etc.)
    flags = ["SYN"],               # TCP flags
    payload = [0x47, 0x45, 0x54]   # Optional payload data
  }
}
```

**TCP fields:**
- `source_port` (required): Source port (number or name)
- `dest_port` (required): Destination port (number or name)
- `flags` (required): Array of TCP flags
- `payload` (optional): Array of bytes for packet payload

**Valid TCP flags:**
- `"SYN"` - Synchronize
- `"ACK"` - Acknowledgment
- `"FIN"` - Finish
- `"RST"` - Reset
- `"PSH"` - Push
- `"URG"` - Urgent

**Common TCP flag combinations:**
```toml
flags = ["SYN"]           # Connection initiation
flags = ["SYN", "ACK"]    # Connection response
flags = ["ACK"]           # Data transfer
flags = ["FIN", "ACK"]    # Connection termination
flags = ["RST"]           # Connection reset
flags = []                # NULL scan (no flags)
```

### UDP Packets

```toml
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  udp = {
    source_port = 53000,
    dest_port = 53,
    payload = [0x12, 0x34, 0x01, 0x00]  # Optional DNS query
  }
}
```

**UDP fields:**
- `source_port` (required): Source port (number or name)
- `dest_port` (required): Destination port (number or name)
- `payload` (optional): Array of bytes for packet payload

### ICMP Packets

```toml
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  icmp = {
    type = 8,                           # Numeric type
    # OR
    type = "echo-request",              # Named type
    code = 0,
    payload = [0x61, 0x62, 0x63, 0x64]  # Optional payload
  }
}
```

**ICMP fields:**
- `type` (required): ICMP type (number or name)
- `code` (required): ICMP code
- `payload` (optional): Array of bytes for packet payload

**Common ICMP types (IPv4):**
- `0` or `"echo-reply"` - Echo reply (ping response)
- `3` - Destination unreachable
- `8` or `"echo-request"` - Echo request (ping)
- `11` - Time exceeded

**IPv6 ICMP type auto-translation:**

When using IPv6 addresses, nftsim automatically translates ICMPv4 types to ICMPv6:
- Type `8` (echo-request) → Type `128` (ICMPv6 echo-request)
- Type `0` (echo-reply) → Type `129` (ICMPv6 echo-reply)

You can use either numeric types or named types like `"echo-request"` which work for both IPv4 and IPv6.

### Payload Data

All protocols support optional payload data as an array of bytes:

```toml
# ASCII text "GET /"
payload = [0x47, 0x45, 0x54, 0x20, 0x2f]

# Binary data
payload = [0x16, 0x03, 0x01, 0x00, 0x05]

# DNS query header
payload = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
```

### IPv6 Packets

IPv6 packets use the same format as IPv4, but with IPv6 addresses:

```toml
packet = {
  on_interface = "eth0",
  source_ip = "2001:db8:1::50",      # IPv6 source
  dest_ip = "2001:db8:8888::8888",   # IPv6 destination
  tcp = { source_port = 50000, dest_port = 443, flags = ["SYN"] }
}
```

IPv6 is auto-detected from address format. No special configuration needed.

## Expectations

Expectations validate packet behavior through nftables hooks. Each expectation specifies a hook and verdict, with optional additional validations.

### Basic Structure

```toml
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" }
]
```

### Hooks

Packets traverse different nftables hooks depending on their path:

- **`prerouting`** - Before routing decision (used for DNAT)
- **`input`** - Packets destined to the firewall itself
- **`forward`** - Packets being forwarded between interfaces
- **`output`** - Packets originating from the firewall (requires guest injection)
- **`postrouting`** - After routing decision (used for SNAT)

**Hook inference:**

If `hook` is omitted, nftsim infers it from `to_interface`:
- With `to_interface`: Assumed `forward` hook
- Without `to_interface`: Assumed `input` hook

```toml
# Explicit hook
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# Inferred forward hook (same as above)
expect = [ { verdict = "accept", to_interface = "eth1" } ]

# Inferred input hook (packet to firewall itself)
expect = [ { verdict = "accept" } ]
```

### Verdicts

- **`accept`** - Packet is accepted
- **`drop`** - Packet is silently dropped
- **`reject`** - Packet is rejected (ICMP error sent)

```toml
# Accept packet
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# Drop packet
expect = [ { hook = "forward", verdict = "drop" } ]

# Reject packet
expect = [ { hook = "forward", verdict = "reject" } ]
```

### Interface Validation

For forwarded packets, specify the expected output interface:

```toml
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" }
]
```

### NAT Validation

#### Source NAT (SNAT/Masquerade)

Validate that a packet's source IP is translated:

```toml
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]
```

**Fields:**
- `hook = "postrouting"` (required for SNAT)
- `src_nat` (required): Expected source IP after translation

#### Destination NAT (DNAT/Port Forwarding)

Validate that a packet's destination IP is translated:

```toml
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]
```

**Fields:**
- `hook = "prerouting"` (required for DNAT)
- `dst_nat` (required): Expected destination IP after translation

#### Bidirectional NAT

Test both SNAT and DNAT on the same packet flow:

```toml
# Inbound packet (DNAT)
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]

# Outbound packet (SNAT)
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]
```

### Multiple Expectations

A single packet can have multiple expectations to validate different hooks:

```toml
# Packet that gets SNAT'd
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]

# Packet that gets DNAT'd
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]
```

### Guest Injection (OUTPUT Hook)

Packets with a firewall IP as source are automatically injected from the guest to test OUTPUT hooks:

```toml
# This packet will be auto-injected from guest because source IP matches firewall interface
packet = {
  on_interface = "eth1",
  source_ip = "192.168.1.1",  # Matches firewall interface eth0
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "output", verdict = "accept" } ]
```

## Complete Examples

### Example 1: Basic Firewall (2 Interfaces)

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },  # Internal
  { name = "eth1", ip = "10.0.0.1/24" },     # External
]

routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# Allow internal to external HTTP
[[tests]]
name = "Internal to External HTTP - Allowed"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# Block external to internal
[[tests]]
name = "External to Internal - Blocked"

[[tests.packets]]
packet = {
  on_interface = "eth1",
  source_ip = "1.2.3.4",
  dest_ip = "192.168.1.50",
  tcp = { source_port = 12345, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "drop" } ]
```

### Example 2: NAT Gateway

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "203.0.113.10/24" },
]

routes = [
  { destination = "0.0.0.0/0", via = "203.0.113.1" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# SNAT (masquerade)
[[tests]]
name = "SNAT - Internal to External"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]

# DNAT (port forwarding)
[[tests]]
name = "DNAT - External to Internal Server"

[[tests.packets]]
packet = {
  on_interface = "eth1",
  source_ip = "1.2.3.4",
  dest_ip = "203.0.113.10",
  tcp = { source_port = 55000, dest_port = 80, flags = ["SYN"] }
}
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]
```

### Example 3: DMZ (3 Interfaces)

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },   # Internal
  { name = "eth1", ip = "203.0.113.10/24" },  # External
  { name = "eth2", ip = "10.99.0.1/24" },     # DMZ
]

routes = [
  { destination = "0.0.0.0/0", via = "203.0.113.1" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# Internal to DMZ web server
[[tests]]
name = "Internal to DMZ Web - Allowed"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.100",
  dest_ip = "10.99.0.50",
  tcp = { source_port = 50000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth2" } ]

# DMZ to internal - blocked
[[tests]]
name = "DMZ to Internal - Blocked"

[[tests.packets]]
packet = {
  on_interface = "eth2",
  source_ip = "10.99.0.50",
  dest_ip = "192.168.1.100",
  tcp = { source_port = 55000, dest_port = 445, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "drop" } ]
```

### Example 4: IPv6 Firewall

```toml
[network]
interfaces = [
  { name = "eth0", ip = "2001:db8:1::1/64" },
  { name = "eth1", ip = "2001:db8:2::1/64" },
]

routes = [
  { destination = "::/0", via = "2001:db8:2::2" },
]

[guest_setup]
sysctls = { "net.ipv6.conf.all.forwarding" = "1" }

# IPv6 TCP
[[tests]]
name = "IPv6 HTTPS Connection"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "2001:db8:1::50",
  dest_ip = "2001:db8:8888::8888",
  tcp = { source_port = 50000, dest_port = 443, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# IPv6 ICMP (auto-translates type 8 → 128)
[[tests]]
name = "IPv6 Ping"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "2001:db8:1::50",
  dest_ip = "2001:db8:8888::1",
  icmp = { type = "echo-request", code = 0 }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

### Example 5: Packet with Payload

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

# TCP with HTTP payload
[[tests]]
name = "HTTP Request with Payload"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = {
    source_port = 45000,
    dest_port = 80,
    flags = ["SYN"],
    payload = [0x47, 0x45, 0x54, 0x20, 0x2f]  # "GET /"
  }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# UDP with DNS query payload
[[tests]]
name = "DNS Query"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  udp = {
    source_port = 53000,
    dest_port = 53,
    payload = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# ICMP with payload
[[tests]]
name = "Ping with Payload"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  icmp = {
    type = 8,
    code = 0,
    payload = [0x61, 0x62, 0x63, 0x64]  # "abcd"
  }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

### Example 6: OUTPUT Hook (Guest Injection)

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "203.0.113.1/24" },
]

routes = [
  { destination = "0.0.0.0/0", via = "203.0.113.2" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

# Test OUTPUT hook - packet from firewall itself
[[tests]]
name = "OUTPUT - Firewall to Internet"

[[tests.packets]]
packet = {
  on_interface = "eth1",
  source_ip = "192.168.1.1",  # Firewall's own IP triggers guest injection
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "output", verdict = "accept" } ]

# Regular FORWARD test for comparison
[[tests]]
name = "FORWARD - Internal to External"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",  # Different IP - uses host injection
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

## Best Practices

### Test Organization

1. **Group related tests** - Keep similar tests together (e.g., all HTTP tests, all NAT tests)
2. **Use descriptive names** - Test names should clearly indicate what's being tested
3. **Order matters** - Place drop/reject tests BEFORE connection-establishing tests to avoid conntrack pollution
4. **Use unique IP pairs** - Avoid conntrack state conflicts by using different IPs for different tests

### Conntrack State Management

Connection tracking state persists across tests. To avoid conflicts:

```toml
# WRONG: Drop test after established connection
[[tests]]
name = "Allow Connection"
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { verdict = "accept", to_interface = "eth1" } ]

[[tests]]
name = "Drop Same IP Later"  # Will likely fail due to conntrack state
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 25, flags = ["SYN"] } }
expect = [ { verdict = "drop" } ]

# RIGHT: Use different IPs or reorder tests
[[tests]]
name = "Drop Connection"
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.51", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 25, flags = ["SYN"] } }
expect = [ { verdict = "drop" } ]

[[tests]]
name = "Allow Connection"
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { verdict = "accept", to_interface = "eth1" } ]
```

### Port Naming

Use well-known port names for readability:

```toml
# Named ports (preferred for common services)
tcp = { source_port = 40000, dest_port = "http" }
tcp = { source_port = 40000, dest_port = "https" }
tcp = { source_port = 40000, dest_port = "ssh" }

# Numeric ports (required for non-standard ports)
tcp = { source_port = 40000, dest_port = 8080 }
```

### ICMP Type Naming

Use named types for clarity, especially with IPv6:

```toml
# Named types (preferred, works for both IPv4 and IPv6)
icmp = { type = "echo-request", code = 0 }
icmp = { type = "echo-reply", code = 0 }

# Numeric types (also supported)
icmp = { type = 8, code = 0 }  # Auto-translates to 128 for IPv6
```

## See Also

- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow and debugging tips
- [DESIGN.md](DESIGN.md) - Architecture and implementation details
- [README.md](README.md) - Project overview and quick start

For example test suites, see the `testdata/` directory:
- `testdata/01_basics.toml` - Basic firewall tests
- `testdata/08_nat.toml` - NAT and port forwarding
- `testdata/12_dmz.toml` - DMZ/3-zone firewall
- `testdata/22_ipv6.toml` - IPv6 support
- `testdata/21_payload.toml` - Payload data examples
- `testdata/26_guest_injection.toml` - OUTPUT hook testing
