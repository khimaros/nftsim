// src/commands/test/guest.rs
//
// Guest injection functions for nftsim
// Handles packet injection from inside the UML guest

use crate::config::SimConfig;
use anyhow::Result;

// Timing constant for guest injection
pub(super) const GUEST_INJECTION_TIMEOUT_SECS: u64 = 1; // Timeout for guest-originated commands (socat/ping)

/// Determine if a packet should be injected from inside the guest (vs from host)
/// Returns true if source IP is a guest interface IP, destination is loopback, or both are guest IPs
pub(super) fn should_inject_from_guest(packet: &crate::config::Packet, config: &SimConfig) -> bool {
    use std::collections::HashSet;

    // Collect all guest interface IPs
    let guest_ips: HashSet<String> = config
        .network
        .interfaces
        .iter()
        .map(|iface| iface.ip.split('/').next().unwrap_or(&iface.ip).to_string())
        .collect();

    // Case 1: Source IP is a guest interface IP (OUTPUT hook test)
    // This covers both OUTPUT hook tests and inter-interface local delivery
    if guest_ips.contains(&packet.source_ip) {
        return true;
    }

    // Case 2: Destination is loopback (INPUT hook for local services)
    if packet.dest_ip == "127.0.0.1" || packet.dest_ip == "::1" {
        return true;
    }

    // Otherwise: inject from host (NAT return packets, external traffic, etc.)
    false
}

/// Build a guest injection command using socat or ping
pub(super) fn build_guest_injection_command(packet: &crate::config::Packet) -> Result<String> {
    let cmd = match &packet.transport {
        crate::config::Transport::Tcp(tcp) => {
            // Use socat to create TCP connection with specific source IP and port
            format!(
                "timeout {} socat -T{} /dev/null TCP:{}:{},bind={}:{},connect-timeout={} 2>/dev/null || true",
                GUEST_INJECTION_TIMEOUT_SECS,
                GUEST_INJECTION_TIMEOUT_SECS,
                packet.dest_ip,
                tcp.dest_port,
                packet.source_ip,
                tcp.source_port,
                GUEST_INJECTION_TIMEOUT_SECS
            )
        }
        crate::config::Transport::Udp(udp) => {
            // Use socat to send UDP packet with specific source IP and port
            format!(
                "timeout {} socat -T{} /dev/null UDP:{}:{},bind={}:{} 2>/dev/null || true",
                GUEST_INJECTION_TIMEOUT_SECS,
                GUEST_INJECTION_TIMEOUT_SECS,
                packet.dest_ip,
                udp.dest_port,
                packet.source_ip,
                udp.source_port
            )
        }
        crate::config::Transport::Icmp(_icmp) => {
            // Use ping with specific source interface
            // For loopback, use -I lo, otherwise use -I <source_ip>
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
