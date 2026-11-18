# TOML test format reference

this document describes the TOML configuration format for defining nftsim test cases.

## table of contents

- [overview](#overview)
- [file structure](#file-structure)
- [network configuration](#network-configuration)
- [guest setup](#guest-setup)
- [test definitions](#test-definitions)
- [packet specifications](#packet-specifications)
- [expectations](#expectations)
- [complete examples](#complete-examples)

## overview

each test suite consists of two files:
- `testdata/NN_name.nft` - the nftables ruleset to test
- `testdata/NN_name.toml` - test configuration and test cases

the TOML file defines the network topology, guest environment setup, and test cases with packet specifications and expectations.

## file structure

a test configuration file has three main sections:

```toml
# optional: the ruleset under test, relative to this file
ruleset = "../etc/nftables.conf"

[network]
# network topology: interfaces and routes

[guest_setup]
# guest environment: sysctls, pre/post commands

[[tests]]
# test cases: packets and expectations
```

with `ruleset` set, the suite runs on its own: `nftsim test suite.toml`. a
ruleset given on the command line (`nftsim test rules.nft suite.toml`) takes
precedence over it.

## network configuration

### interfaces

define network interfaces with one or more IP addresses (IPv4, IPv6 or both):

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "10.0.0.1/24" },
  { name = "eth2", ip = "2001:db8:1::1/64" },                       # IPv6
  { name = "eth3", ips = ["203.0.113.10/24", "2001:db8:3::10/64"] },  # dual-stack
]
```

**fields:**
- `name` (required): interface name (e.g., "eth0", "eth1")
- `ip`: one IP address with CIDR notation (IPv4 or IPv6)
- `ips`: a list of IP addresses with CIDR notation, added after `ip`

every interface needs at least one address from `ip` or `ips`. IPv6 addresses
skip duplicate address detection, so they are usable as soon as the guest is up.

every configured address counts as the guest's own: a packet whose
`source_ip` is any of them is injected from inside the guest (OUTPUT hook).
for masquerade, `src_nat` is checked against the address the kernel actually
chose, read from the guest's conntrack table. on an interface with several
addresses this is the one masquerade selects for the route (for example the
address on the default gateway's subnet), and an IPv6 packet gets an IPv6
address.

### routes

define static routes:

```toml
routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },        # IPv4 default route
  { destination = "::/0", via = "2001:db8:2::2" },        # IPv6 default route
  { destination = "192.168.0.0/16", via = "10.0.0.3" },   # specific network
]
```

**fields:**
- `destination` (required): destination network in CIDR notation
- `via` (required): gateway IP address

## guest setup

configure the UML guest environment:

```toml
[guest_setup]
sysctls = {
  "net.ipv4.ip_forward" = "1",
  "net.ipv6.conf.all.forwarding" = "1",
  "net.ipv4.conf.all.rp_filter" = "0",
}

pre_nft_commands = [
  "ip link set eth0 up",
  "echo 'Custom setup command'",
]

post_nft_commands = [
  "nft list ruleset",
]
```

**fields:**
- `sysctls` (optional): key-value pairs of sysctl settings
- `pre_nft_commands` (optional): shell commands to run before loading nftables rules
- `post_nft_commands` (optional): shell commands to run after loading nftables rules

`pre_nft_commands` can stand in for tables other tools add at runtime (Docker,
wg-quick) and can load the ruleset once (`nft -f /mnt/host/rules.nft`), so the
harness's own load tests a reload over a live ruleset. traces report a verdict
under the hook its base chain is attached to, whatever the chain is named.

## test definitions

tests are defined using TOML table arrays:

```toml
[[tests]]
name = "test name"

[[tests.packets]]
packet = { ... }
expect = [ ... ]

[[tests.packets]]
packet = { ... }
expect = [ ... ]
```

**test fields:**
- `name` (required): descriptive test name

**packet fields:**
- `packet` (required): packet specification (see [packet specifications](#packet-specifications))
- `expect` (required): array of expectations (see [expectations](#expectations))

## packet specifications

all packets must specify:
- `on_interface`: interface name where the packet enters/exits
- `source_ip`: source IP address (IPv4 or IPv6)
- `dest_ip`: destination IP address (IPv4 or IPv6)
- protocol-specific fields: `tcp`, `udp`, or `icmp`

### TCP packets

```toml
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = {
    source_port = 40000,           # numeric port
    dest_port = "http",            # or named port ("http", "https", "ssh", etc.)
    flags = ["SYN"],               # TCP flags
    payload = [0x47, 0x45, 0x54]   # optional payload data
  }
}
```

**TCP fields:**
- `source_port` (required): source port (number or name)
- `dest_port` (required): destination port (number or name)
- `flags` (required): array of TCP flags
- `payload` (optional): array of bytes for packet payload

**valid TCP flags:**
- `"SYN"` - synchronize
- `"ACK"` - acknowledgment
- `"FIN"` - finish
- `"RST"` - reset
- `"PSH"` - push
- `"URG"` - urgent

**common TCP flag combinations:**
```toml
flags = ["SYN"]           # connection initiation
flags = ["SYN", "ACK"]    # connection response
flags = ["ACK"]           # data transfer
flags = ["FIN", "ACK"]    # connection termination
flags = ["RST"]           # connection reset
flags = []                # NULL scan (no flags)
```

### UDP packets

```toml
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  udp = {
    source_port = 53000,
    dest_port = 53,
    payload = [0x12, 0x34, 0x01, 0x00]  # optional DNS query
  }
}
```

**UDP fields:**
- `source_port` (required): source port (number or name)
- `dest_port` (required): destination port (number or name)
- `payload` (optional): array of bytes for packet payload

### ICMP packets

```toml
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  icmp = {
    type = 8,                           # numeric type
    # OR
    type = "echo-request",              # named type
    code = 0,
    payload = [0x61, 0x62, 0x63, 0x64]  # optional payload
  }
}
```

**ICMP fields:**
- `type` (required): ICMP type (number or name)
- `code` (required): ICMP code
- `payload` (optional): array of bytes for packet payload

**common ICMP types (IPv4):**
- `0` or `"echo-reply"` - echo reply (ping response)
- `3` - destination unreachable
- `8` or `"echo-request"` - echo request (ping)
- `11` - time exceeded

**IPv6 ICMP type auto-translation:**

when using IPv6 addresses, nftsim translates ICMPv4 types to ICMPv6:
- type `8` (echo-request) -> type `128` (ICMPv6 echo-request)
- type `0` (echo-reply) -> type `129` (ICMPv6 echo-reply)

named types like `"echo-request"` work for both IPv4 and IPv6, as do numeric types.

### payload data

all protocols support optional payload data as an array of bytes:

```toml
# ASCII text "GET /"
payload = [0x47, 0x45, 0x54, 0x20, 0x2f]

# binary data
payload = [0x16, 0x03, 0x01, 0x00, 0x05]

# DNS query header
payload = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
```

### IPv6 packets

IPv6 packets use the same format as IPv4, but with IPv6 addresses:

```toml
packet = {
  on_interface = "eth0",
  source_ip = "2001:db8:1::50",      # IPv6 source
  dest_ip = "2001:db8:8888::8888",   # IPv6 destination
  tcp = { source_port = 50000, dest_port = 443, flags = ["SYN"] }
}
```

IPv6 is detected from the address format, so it needs no special configuration.

## expectations

expectations validate packet behavior through nftables hooks. each expectation specifies a hook and verdict, with optional additional validations.

### basic structure

```toml
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" }
]
```

### hooks

packets traverse different nftables hooks depending on their path:

- **`prerouting`** - before the routing decision (used for DNAT)
- **`input`** - packets destined to the firewall itself
- **`forward`** - packets being forwarded between interfaces
- **`output`** - packets originating from the firewall (requires guest injection)
- **`postrouting`** - after the routing decision (used for SNAT)

**hook inference:**

if `hook` is omitted, nftsim infers it from `to_interface`:
- with `to_interface`: `forward` hook
- without `to_interface`: `input` hook

```toml
# explicit hook
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# inferred forward hook (same as above)
expect = [ { verdict = "accept", to_interface = "eth1" } ]

# inferred input hook (packet to firewall itself)
expect = [ { verdict = "accept" } ]
```

### verdicts

- **`accept`** - packet is accepted
- **`drop`** - packet is silently dropped
- **`reject`** - packet is rejected (ICMP error sent)

```toml
# accept packet
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# drop packet
expect = [ { hook = "forward", verdict = "drop" } ]

# reject packet
expect = [ { hook = "forward", verdict = "reject" } ]
```

### interface validation

for forwarded packets, specify the expected output interface:

```toml
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" }
]
```

### NAT validation

#### source NAT (SNAT/masquerade)

validate that a packet's source IP is translated:

```toml
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]
```

**fields:**
- `hook = "postrouting"` (required for SNAT)
- `src_nat` (required): expected source IP after translation

#### destination NAT (DNAT/port forwarding)

validate that a packet's destination IP is translated:

```toml
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]
```

**fields:**
- `hook = "prerouting"` (required for DNAT)
- `dst_nat` (required): expected destination IP after translation

#### bidirectional NAT

test both SNAT and DNAT on the same packet flow:

```toml
# inbound packet (DNAT)
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]

# outbound packet (SNAT)
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]
```

### multiple expectations

a single packet can have multiple expectations to validate different hooks:

```toml
# packet that gets SNAT'd
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" }
]

# packet that gets DNAT'd
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" }
]
```

### guest injection (OUTPUT hook)

packets with a firewall IP as source are injected from the guest to test OUTPUT hooks:

```toml
# injected from the guest because the source IP matches a firewall interface
packet = {
  on_interface = "eth1",
  source_ip = "192.168.1.1",  # matches firewall interface eth0
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "output", verdict = "accept" } ]
```

## complete examples

### example 1: basic firewall (2 interfaces)

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },  # internal
  { name = "eth1", ip = "10.0.0.1/24" },     # external
]

routes = [
  { destination = "0.0.0.0/0", via = "10.0.0.2" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

[[tests]]
name = "internal to external HTTP - allowed"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",
  dest_ip = "8.8.8.8",
  tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

[[tests]]
name = "external to internal - blocked"

[[tests.packets]]
packet = {
  on_interface = "eth1",
  source_ip = "1.2.3.4",
  dest_ip = "192.168.1.50",
  tcp = { source_port = 12345, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "drop" } ]
```

### example 2: NAT gateway

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
name = "SNAT - internal to external"

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
name = "DNAT - external to internal server"

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

### example 3: DMZ (3 interfaces)

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },   # internal
  { name = "eth1", ip = "203.0.113.10/24" },  # external
  { name = "eth2", ip = "10.99.0.1/24" },     # DMZ
]

routes = [
  { destination = "0.0.0.0/0", via = "203.0.113.1" },
]

[guest_setup]
sysctls = { "net.ipv4.ip_forward" = "1" }

[[tests]]
name = "internal to DMZ web - allowed"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.100",
  dest_ip = "10.99.0.50",
  tcp = { source_port = 50000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth2" } ]

[[tests]]
name = "DMZ to internal - blocked"

[[tests.packets]]
packet = {
  on_interface = "eth2",
  source_ip = "10.99.0.50",
  dest_ip = "192.168.1.100",
  tcp = { source_port = 55000, dest_port = 445, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "drop" } ]
```

### example 4: IPv6 firewall

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

[[tests]]
name = "IPv6 HTTPS connection"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "2001:db8:1::50",
  dest_ip = "2001:db8:8888::8888",
  tcp = { source_port = 50000, dest_port = 443, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]

# IPv6 ICMP (translates type 8 -> 128)
[[tests]]
name = "IPv6 ping"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "2001:db8:1::50",
  dest_ip = "2001:db8:8888::1",
  icmp = { type = "echo-request", code = 0 }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

### example 5: packet with payload

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
name = "HTTP request with payload"

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

[[tests]]
name = "DNS query"

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

[[tests]]
name = "ping with payload"

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

### example 6: OUTPUT hook (guest injection)

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

# packet from the firewall itself
[[tests]]
name = "OUTPUT - firewall to internet"

[[tests.packets]]
packet = {
  on_interface = "eth1",
  source_ip = "192.168.1.1",  # the firewall's own IP triggers guest injection
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "output", verdict = "accept" } ]

# regular FORWARD test for comparison
[[tests]]
name = "FORWARD - internal to external"

[[tests.packets]]
packet = {
  on_interface = "eth0",
  source_ip = "192.168.1.50",  # a non-firewall IP uses host injection
  dest_ip = "8.8.8.8",
  tcp = { source_port = 45000, dest_port = 80, flags = ["SYN"] }
}
expect = [ { hook = "forward", verdict = "accept", to_interface = "eth1" } ]
```

## best practices

### test organization

1. **group related tests** - keep similar tests together (e.g., all HTTP tests, all NAT tests)
2. **use descriptive names** - test names should say what is being tested
3. **order matters** - place drop/reject tests BEFORE connection-establishing tests to avoid conntrack pollution
4. **use unique IP pairs** - avoid conntrack state conflicts by using different IPs for different tests

### conntrack state management

connection tracking state persists across tests. to avoid conflicts:

```toml
# WRONG: drop test after established connection
[[tests]]
name = "allow connection"
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { verdict = "accept", to_interface = "eth1" } ]

[[tests]]
name = "drop same IP later"  # will likely fail due to conntrack state
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 25, flags = ["SYN"] } }
expect = [ { verdict = "drop" } ]

# RIGHT: use different IPs or reorder tests
[[tests]]
name = "drop connection"
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.51", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 25, flags = ["SYN"] } }
expect = [ { verdict = "drop" } ]

[[tests]]
name = "allow connection"
[[tests.packets]]
packet = { on_interface = "eth0", source_ip = "192.168.1.50", dest_ip = "8.8.8.8", tcp = { source_port = 40000, dest_port = 80, flags = ["SYN"] } }
expect = [ { verdict = "accept", to_interface = "eth1" } ]
```

### port naming

use well-known port names for readability:

```toml
# named ports (preferred for common services)
tcp = { source_port = 40000, dest_port = "http" }
tcp = { source_port = 40000, dest_port = "https" }
tcp = { source_port = 40000, dest_port = "ssh" }

# numeric ports (required for non-standard ports)
tcp = { source_port = 40000, dest_port = 8080 }
```

### ICMP type naming

use named types for clarity, especially with IPv6:

```toml
# named types (preferred, works for both IPv4 and IPv6)
icmp = { type = "echo-request", code = 0 }
icmp = { type = "echo-reply", code = 0 }

# numeric types (also supported)
icmp = { type = 8, code = 0 }  # translates to 128 for IPv6
```

## see also

- [CONTRIBUTING.md](CONTRIBUTING.md) - development workflow and debugging tips
- [DESIGN.md](DESIGN.md) - architecture and implementation details
- [README.md](README.md) - project overview and quick start

for example test suites, see the `testdata/` directory:
- `testdata/01_basics.toml` - basic firewall tests
- `testdata/08_nat.toml` - NAT and port forwarding
- `testdata/12_dmz.toml` - DMZ/3-zone firewall
- `testdata/22_ipv6.toml` - IPv6 support
- `testdata/21_payload.toml` - payload data examples
- `testdata/26_guest_injection.toml` - OUTPUT hook testing
