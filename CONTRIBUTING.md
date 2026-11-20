# contributing to nftsim

development workflow, test commands and common pitfalls. for first-time bootstrap see [README.md](README.md); for architecture see [DESIGN.md](DESIGN.md); for TOML test syntax see [TESTDATA.md](TESTDATA.md).

## build, test and lint

```bash
make                        # release build (./target/release/nftsim)
./test.sh                   # all 26 test suites (321 cases)
./test.sh 01_basics 08_nat  # specific suites
make test-e2e               # Python end-to-end tests (tests/e2e/)
make precommit              # cargo clippy, cargo test, shellcheck, ruff
```

### debugging a suite

```bash
./target/release/nftsim test FILE.nft FILE.toml --verbose --trace --keep-temp
```

inspect logs using the exact temporary directory printed by the run (never wildcards):
- `trace.log` - `nft monitor trace` output
- `trace_monitor.err` - `nft monitor trace` stderr
- `test.log` - verbose orchestrator log
- `harness.log` - guest setup log
- `commands.log` - guest `EXEC` output
- `uml_stdout.log` / `uml_stderr.log` - UML kernel output

verify ruleset syntax offline with `nft -c -f testdata/XX.nft`.

## test suites

`./test.sh` runs 26 suites (321 test cases), inverting pass/fail for `SHOULD_FAIL:` cases and exiting 1 on any unexpected failure:

| suite                  | tests | description                                                  |
| ---------------------- | ----- | ------------------------------------------------------------ |
| 01_basics              | 9     | TCP firewall basics, concurrent connections, port ranges     |
| 02_verdict_validation  | 40    | expectation validation framework (includes SHOULD_FAIL)      |
| 03_accept_verdict      | 4     | INPUT hook acceptance                                        |
| 04_udp                 | 5     | UDP protocol support (DNS queries)                           |
| 05_icmp                | 5     | ICMP echo-request/reply                                      |
| 06_conntrack           | 10    | connection tracking, state management, reuse                 |
| 07_mixed               | 12    | multi-protocol scenarios, protocol transitions               |
| 08_nat                 | 9     | SNAT, DNAT, masquerade                                       |
| 09_rate_limiting       | 6     | rate limit rules                                             |
| 10_port_forwarding     | 7     | DNAT port forwarding                                         |
| 11_security            | 9     | security policies, interface-based filtering                 |
| 12_dmz                 | 13    | 3-zone DMZ firewall                                          |
| 13_sets                | 12    | sets, intervals, maps                                        |
| 14_quotas              | 8     | counters and quotas                                          |
| 15_stress              | 3     | high-volume stress testing (50+ connections)                 |
| 16_tcp_flags           | 9     | TCP flag validation (NULL, XMAS, invalid combinations)       |
| 17_icmp_types          | 12    | extended ICMP types, conntrack pollution                     |
| 18_ttl_validation      | 6     | TTL/hop limit validation                                     |
| 19_protocol_edge_cases | 8     | protocol edge cases, multi-service validation                |
| 20_advanced_nat        | 8     | NAT port ranges, multi-interface NAT                         |
| 21_payload             | 9     | TCP/UDP/ICMP payload data                                    |
| 22_ipv6                | 5     | IPv6 dual-stack and ICMPv6 type translation                  |
| 23_docker_host         | 25    | Docker host with VPN, NAT, container port forwarding         |
| 24_vpn_gateway         | 52    | VPN gateway with peer routing, masquerade, port forwarding   |
| 25_laptop              | 32    | laptop firewall with selective service access                |
| 26_guest_injection     | 3     | OUTPUT and INPUT hooks with automatic guest injection        |

### end-to-end tests (`tests/e2e/`, run via `make test-e2e`)

- `test_stability.py` - concurrent runs sharing `rootfs.img` (COW overlay) and `24_vpn_gateway` under full CPU load
- `test_dual_stack.py` - multi-address dual-stack gateway, guest injection from a secondary address, conntrack masquerade check
- `test_reliability.py` - hard failure on `READY` timeout, dead trace monitor detection (including on drop-only suites), per-step trace isolation on repeated 5-tuples, and unrecognized trace line rejection

## adding a test suite

1. create `testdata/NN_name.nft` and `testdata/NN_name.toml` (see [TESTDATA.md](TESTDATA.md))
2. add `NN_name` to `all_suites` in `test.sh`
3. verify with `./test.sh NN_name`, then `./test.sh`, `make test-e2e` and `make precommit`
4. update the suite table and counts here and in [README.md](README.md)

## common pitfalls

- **conntrack state pollution**: conntrack state persists across tests in one UML guest. place drop/reject tests before connection-establishing tests or use unique IP/port tuples (see `testdata/17_icmp_types.toml`).
- **subshell variable scope in `res/harness.sh`**: avoid `tail -f file | while read`; variables mutated inside a pipeline subshell do not persist. read lines by index with `sed -n "${n}p"` and split with shell parameter expansion.
- **missing NAT trace**: if NAT expectations fail with "no NAT detected in trace", check `harness.log` to confirm `meta nftrace set 1` succeeded on every NAT chain.
- **IPv6 ICMP rules**: write `icmpv6` rules (e.g. `icmpv6 type echo-request`) for IPv6 traffic; nftsim translates ICMPv4 test types (`8` -> `128`, `0` -> `129`) automatically.
- **Debian bookworm rootfs**: `res/bootstrap.sh` pins Debian **bookworm** because `mount` in Debian forky/testing uses the new mount API (`fsconfig`), which UML's `hostfs` driver does not yet support.
