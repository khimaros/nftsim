# TOML test format reference

a test suite pairs an nftables ruleset (`*.nft`) with a TOML config (`*.toml`). a suite can also name its own ruleset with a top-level `ruleset` path (relative to the TOML file) and run via `nftsim test suite.toml`; a ruleset passed on the command line takes precedence.

## top-level structure

```toml
# optional: ruleset path relative to this file
ruleset = "../etc/nftables.conf"

[network]
# interfaces and static routes

[guest_setup]
# sysctls and pre/post nft shell commands

[[tests]]
# test cases with [[tests.packets]] steps
```

rulesets can alternatively embed `# !` test directives directly without a TOML file (see `testdata/27_gateway_embedded.nft`).

## `[network]`

### `interfaces`

each interface requires `name` and at least one CIDR address via `ip`, `ips` (added after `ip`), or both:

```toml
[network]
interfaces = [
  { name = "eth0", ip = "192.168.1.1/24" },
  { name = "eth1", ip = "2001:db8:1::1/64" },
  { name = "eth2", ips = ["203.0.113.10/24", "2001:db8:2::10/64"] },
]
```

- IPv6 addresses are configured with `nodad` so they are usable immediately at boot.
- any packet whose `source_ip` matches any configured interface address is injected from inside the guest (testing the `output` hook).
- for masquerade, `src_nat` is verified against the address the kernel chose in `/proc/net/nf_conntrack`.

### `routes`

```toml
routes = [
  { destination = "0.0.0.0/0", via = "203.0.113.1" },
  { destination = "::/0", via = "2001:db8:2::1" },
  { destination = "192.168.0.0/16", via = "10.0.0.3" },
]
```

## `[guest_setup]`

all fields are optional:

```toml
[guest_setup]
sysctls = {
  "net.ipv4.ip_forward" = "1",
  "net.ipv6.conf.all.forwarding" = "1",
}
pre_nft_commands = ["echo 'runs before ruleset load'"]
post_nft_commands = ["nft list ruleset"]
```

`pre_nft_commands` runs before `nft -f /mnt/host/rules.nft`, so it can create tables added at runtime by external tools (Docker, wg-quick) or pre-load a ruleset to test a reload.

## `[[tests]]` and `[[tests.packets]]`

```toml
[[tests]]
name = "allow HTTP handshake"

[[tests.packets]]
packet = { ... }
expect = [ ... ]
```

### `packet` fields

every packet requires `on_interface`, `source_ip`, `dest_ip` (IPv4 or IPv6, detected from address format) and one transport table:

- **TCP**: `tcp = { source_port = 40000, dest_port = "http", flags = ["SYN"], payload = [0x47, 0x45, 0x54] }`
  - `source_port`, `dest_port`: numeric or well-known service name (`"http"`, `"https"`, `"ssh"`, etc.)
  - `flags`: array of `"SYN"`, `"ACK"`, `"FIN"`, `"RST"`, `"PSH"`, `"URG"` (`[]` for NULL scan)
  - `payload` (optional): byte array
- **UDP**: `udp = { source_port = 53000, dest_port = 53, payload = [0x12, 0x34] }`
  - `source_port`, `dest_port`: numeric or named; `payload` optional
- **ICMP**: `icmp = { type = "echo-request", code = 0, payload = [0x61, 0x62] }`
  - `type`: numeric (`0`, `3`, `8`, `11`, ...) or named (`"echo-request"`, `"echo-reply"`)
  - `code`: numeric; `payload` optional
  - IPv6 auto-translation: ICMPv4 type `8` translates to ICMPv6 `128`, and `0` to `129`

### `expect` fields

each entry in `expect` validates one hook traversed by the packet:

- `verdict` (required): `"accept"`, `"drop"`, or `"reject"` (lowercase)
- `hook` (optional): `"prerouting"`, `"input"`, `"forward"`, `"output"`, or `"postrouting"`. omitted hooks default to `"forward"` when `to_interface` is set, otherwise `"input"`. base chains are resolved to their hook regardless of chain name
- `to_interface` (optional): expected output interface (`oif` in trace)
- `src_nat` (optional): expected translated source IP (SNAT or masquerade, checked on `postrouting`)
- `dst_nat` (optional): expected translated destination IP (DNAT, checked on `prerouting`)

```toml
# forwarded packet with masquerade
expect = [
  { hook = "forward", verdict = "accept", to_interface = "eth1" },
  { hook = "postrouting", verdict = "accept", src_nat = "203.0.113.10" },
]

# DNAT port forward
expect = [
  { hook = "prerouting", verdict = "accept", dst_nat = "192.168.1.50" },
  { hook = "forward", verdict = "accept", to_interface = "eth0" },
]

# guest-originated packet (source_ip matches a guest interface)
expect = [ { hook = "output", verdict = "accept" } ]
```

## conntrack state across tests

all tests in a suite share one UML guest and its conntrack table. place drop/reject tests before connection-establishing tests, or use distinct IP/port tuples per test so earlier established entries do not affect later checks.

## examples in `testdata/`

- `testdata/01_basics.toml` - basic forwarding, TCP handshakes and named ports
- `testdata/08_nat.toml` - SNAT, masquerade and DNAT port forwarding
- `testdata/12_dmz.toml` - 3-interface DMZ policy
- `testdata/21_payload.toml` - TCP, UDP and ICMP payloads
- `testdata/22_ipv6.toml` - IPv6 forwarding and ICMPv6 translation
- `testdata/26_guest_injection.toml` - `output` hook testing via guest injection
- `tests/e2e/fixtures/dual_stack.toml` - self-contained dual-stack gateway with `ruleset`
