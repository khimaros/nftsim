# ROADMAP

## Known Limitations

- UML ACK packets in established connections may not be captured (lenient validation mode handles this)
- Loopback interface (127.0.0.1) testing not supported in UML
- IPv6 link-local addresses (fe80::/64) don't route properly in UML
- File-based message protocol has 10ms polling overhead

## Planned

### High Priority: Control Channel Migration

```
[ ] phase 1: basic socketpair (replace file polling)
    - create socketpair(AF_UNIX, SOCK_STREAM) in orchestrator
    - pass socket FD to UML guest
    - implement line-based message reader/writer
    - wait for READY signal (event-driven)
    - benefit: eliminate 10ms polling overhead

[ ] phase 2: streaming trace output
    - guest pipes 'nft monitor trace' to socket with TRACE prefix
    - host maintains in-memory trace buffer
    - parse trace incrementally as lines arrive
    - benefit: remove trace file polling delays (~1.3s savings per test)

[ ] phase 3: error handling and diagnostics
    - add ERROR messages from guest
    - add PING/PONG for health checking
    - structured error responses with context
    - benefit: better debugging and reliability

[ ] phase 4: orchestrated guest setup
    - move res/harness.sh logic into Rust
    - execute setup commands step-by-step via EXEC
    - full visibility into each setup phase
    - benefit: cleaner error messages, fail-fast behavior
```

**Enhanced Message Protocol** (for socketpair implementation):

Host → Guest: `EXEC <command>`, `SHUTDOWN`, `PING`
Guest → Host: `READY`, `ACK <exit_code>`, `TRACE <line>`, `ERROR <msg>`, `PONG`

**Migration Strategy**:
- Implement behind `--use-socketpair` flag
- Parallel testing with both approaches
- Enable by default after validation
- Remove file-based approach in next major version

**Expected Performance**: ~85% reduction in test overhead (from ~1.5s to ~0.2s per test)

### Medium Priority

```
[ ] packet fragmentation handling
[ ] dynamic firewall readiness detection
[ ] VLAN tagging support
[ ] performance/stress testing mode enhancements
[ ] support new mount API in UML hostfs (to allow Debian forky/testing)
```

### Low Priority

```
[ ] cleanup CLI output consistency across commands
[ ] upstream kernel config changes to user-mode-linux package
[ ] build rootfs as unprivileged user
    http://stevieo.freeshell.org/uml/adminless-uml-d-i.html
```

## Completed

```
[x] embed res/ scripts and kernel binary into nftsim release
[x] move build directory to $HOME/.local/share/nftsim
[x] build linux.uml reproducibly as unprivileged user
[x] cleanup verbose output
[x] enable testing of packets from inside the guest (OUTPUT hook)
[x] split commands/test.rs into separate files
```
