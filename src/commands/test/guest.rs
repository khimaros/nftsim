// packet injection from inside the UML guest

use crate::config::{SimConfig, is_ipv6};
use anyhow::Result;

/// timeout for guest-originated commands (socat/ping)
pub(super) const GUEST_INJECTION_TIMEOUT_SECS: u64 = 1;

/// decide whether a packet must originate inside the guest: locally generated
/// traffic (source is a guest interface IP) and loopback traffic never cross
/// the host-side sockets, so only the guest can produce them
pub(super) fn should_inject_from_guest(packet: &crate::config::Packet, config: &SimConfig) -> bool {
    use std::collections::HashSet;

    let guest_ips: HashSet<String> = config
        .network
        .interfaces
        .iter()
        .flat_map(|iface| iface.addresses().map(str::to_string))
        .collect();

    // covers OUTPUT hook tests and inter-interface local delivery
    if guest_ips.contains(&packet.source_ip) {
        return true;
    }

    // INPUT hook tests for local services
    if packet.dest_ip == "127.0.0.1" || packet.dest_ip == "::1" {
        return true;
    }

    // NAT return packets, external traffic, etc. come from the host
    false
}

/// format an address and port for socat, which only parses an IPv6 address
/// when it is bracketed
fn socat_endpoint(ip: &str, port: u16) -> String {
    if is_ipv6(ip) {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }
}

/// build the shell command the guest runs to emit the packet, using socat for
/// TCP/UDP so the source address and port can be bound, and ping for ICMP
pub(super) fn build_guest_injection_command(packet: &crate::config::Packet) -> Result<String> {
    let cmd = match &packet.transport {
        crate::config::Transport::Tcp(tcp) => {
            format!(
                "timeout {} socat -T{} /dev/null TCP:{},bind={},connect-timeout={} 2>/dev/null || true",
                GUEST_INJECTION_TIMEOUT_SECS,
                GUEST_INJECTION_TIMEOUT_SECS,
                socat_endpoint(&packet.dest_ip, tcp.dest_port),
                socat_endpoint(&packet.source_ip, tcp.source_port),
                GUEST_INJECTION_TIMEOUT_SECS
            )
        }
        crate::config::Transport::Udp(udp) => {
            format!(
                "timeout {} socat -T{} /dev/null UDP:{},bind={} 2>/dev/null || true",
                GUEST_INJECTION_TIMEOUT_SECS,
                GUEST_INJECTION_TIMEOUT_SECS,
                socat_endpoint(&packet.dest_ip, udp.dest_port),
                socat_endpoint(&packet.source_ip, udp.source_port)
            )
        }
        crate::config::Transport::Icmp(_icmp) => {
            // loopback sources are selected by device rather than by address
            let source_arg = if packet.source_ip == "127.0.0.1" || packet.source_ip == "::1" {
                "-I lo".to_string()
            } else {
                format!("-I {}", packet.source_ip)
            };

            format!(
                "ping -c1 -W1 {} {} 2>/dev/null >/dev/null || true",
                source_arg, packet.dest_ip
            )
        }
    };

    Ok(cmd)
}
