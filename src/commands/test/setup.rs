// guest startup script generation and interface socket creation

use crate::config::{SimConfig, is_ipv6};
use anyhow::{Context, Result};
use std::os::unix::net::UnixStream;

/// generate the guest's startup script, which configures interfaces, sysctls
/// and routes, then hands off to harness.sh. init.sh has already mounted
/// /proc, /sys, /mnt/host and /lib/modules from the kernel cmdline params
pub(super) fn generate_entrypoint_script(config: &SimConfig) -> String {
    let mut script = vec![
        "#!/bin/sh".to_string(),
        "set -eux".to_string(),
    ];

    for (idx, iface) in config.network.interfaces.iter().enumerate() {
        script.push(format!("ip link set vec{} down", idx));
        script.push(format!("ip link set vec{} name {}", idx, iface.name));
        for ip in &iface.ips {
            // skipping DAD keeps IPv6 addresses from sitting tentative, and
            // unusable as a source, when the first test packet arrives
            let nodad = if is_ipv6(ip) { " nodad" } else { "" };
            script.push(format!("ip addr add {} dev {}{}", ip, iface.name, nodad));
        }
        script.push(format!("ip link set {} up", iface.name));
    }
    for (key, value) in &config.guest_setup.sysctls {
        script.push(format!("sysctl -w {}={}", key, value));
    }
    for route in &config.network.routes {
        let family = if is_ipv6(&route.destination) || is_ipv6(&route.via) { "-6 " } else { "" };
        script.push(format!(
            "ip {}route add {} via {}",
            family, route.destination, route.via
        ));
    }

    // harness.sh loads the ruleset, starts tracing, and handles shutdown
    script.push("exec /mnt/host/harness.sh".to_string());

    script.join("\n")
}

/// create one Unix socketpair per network interface, returning the
/// orchestrator ends and the UML ends as (orchestrator_sockets, uml_sockets)
pub(super) fn create_interface_socketpairs(
    config: &SimConfig,
) -> Result<(Vec<UnixStream>, Vec<UnixStream>)> {
    let mut orchestrator_sockets = Vec::new();
    let mut uml_sockets = Vec::new();

    for iface in &config.network.interfaces {
        let (ours, theirs) = UnixStream::pair()
            .context(format!("failed to create socketpair for {}", iface.name))?;
        orchestrator_sockets.push(ours);
        uml_sockets.push(theirs);
    }

    Ok((orchestrator_sockets, uml_sockets))
}
