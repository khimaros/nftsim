// src/commands/test/setup.rs
//
// Environment setup functions for nftsim
// Handles UML guest startup script generation and socket creation

use crate::config::SimConfig;
use anyhow::{Context, Result};
use std::os::unix::net::UnixStream;

/// Generates the guest's main startup script that configures interfaces then calls harness.sh
/// Note: /proc, /sys, /mnt/host, and /lib/modules are already mounted by init.sh based on cmdline params
pub(super) fn generate_entrypoint_script(config: &SimConfig) -> String {
    let mut script = vec![
        "#!/bin/sh".to_string(),
        "set -eux".to_string(),
    ];

    for (idx, iface) in config.network.interfaces.iter().enumerate() {
        script.push(format!("ip link set vec{} down", idx));
        script.push(format!("ip link set vec{} name {}", idx, iface.name));
        script.push(format!("ip addr add {} dev {}", iface.ip, iface.name));
        script.push(format!("ip link set {} up", iface.name));
    }
    for (key, value) in &config.guest_setup.sysctls {
        script.push(format!("sysctl -w {}={}", key, value));
    }
    for route in &config.network.routes {
        script.push(format!(
            "ip route add {} via {}",
            route.destination, route.via
        ));
    }

    // Call harness.sh which handles nft load, trace, and shutdown
    script.push("exec /mnt/host/harness.sh".to_string());

    script.join("\n")
}

/// Creates Unix socketpairs for network interfaces.
/// Returns (orchestrator_sockets, uml_sockets)
pub(super) fn create_interface_socketpairs(
    config: &SimConfig,
) -> Result<(Vec<UnixStream>, Vec<UnixStream>)> {
    let mut orchestrator_sockets = Vec::new();
    let mut uml_sockets = Vec::new();

    for iface in &config.network.interfaces {
        let (ours, theirs) = UnixStream::pair()
            .context(format!("Failed to create socketpair for {}", iface.name))?;
        orchestrator_sockets.push(ours);
        uml_sockets.push(theirs);
    }

    Ok((orchestrator_sockets, uml_sockets))
}
