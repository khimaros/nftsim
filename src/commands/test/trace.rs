// src/commands/test/trace.rs
//
// Trace parsing functions for nftsim
// Parses nftables trace output to extract verdicts, hooks, and NAT information

use std::collections::HashMap;

/// Parsed trace information for a packet
#[derive(Debug, Clone)]
pub(super) struct TraceInfo {
    pub hook_verdicts: HashMap<String, String>, // Hook -> verdict mapping (e.g., "FORWARD" -> "accept")
    pub oif: Option<String>,                    // output interface (for forwarded packets)
    pub iif: String,                            // input interface
    pub src_nat: Option<String>,                // SNAT address
    pub dst_nat: Option<String>,                // DNAT address
}

/// Parse trace content to find a specific packet and extract its routing/verdict information
/// Returns None if packet not found in trace
pub(super) fn parse_trace_for_packet(
    trace_content: &str,
    iface: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    iface_ips: &HashMap<String, String>,
) -> Option<TraceInfo> {
    let mut trace_id: Option<String> = None;
    let mut info = TraceInfo {
        hook_verdicts: HashMap::new(),
        oif: None,
        iif: String::new(),
        src_nat: None,
        dst_nat: None,
    };

    // First pass: find our packet and get its trace ID
    // Try matching on iif first (most common case), then fall back to oif (for OUTPUT hook)
    for line in trace_content.lines() {
        // Match both IPv4 and IPv6 addresses
        let ip_matches = line.contains("packet:")
            && line.contains(&format!("iif \"{}\"", iface))
            && ((line.contains(&format!("ip saddr {}", src_ip))
                && line.contains(&format!("ip daddr {}", dst_ip)))
                || (line.contains(&format!("ip6 saddr {}", src_ip))
                    && line.contains(&format!("ip6 daddr {}", dst_ip))));

        if ip_matches {
            // Check if ports match (for TCP/UDP)
            let ports_match = if let (Some(sp), Some(dp)) = (src_port, dst_port) {
                (line.contains(&format!("tcp sport {}", sp))
                    && line.contains(&format!("tcp dport {}", dp)))
                    || (line.contains(&format!("udp sport {}", sp))
                        && line.contains(&format!("udp dport {}", dp)))
            } else {
                // ICMP or no ports to match
                line.contains("icmp") || line.contains("icmpv6")
            };

            if ports_match {
                // Extract trace ID
                if let Some(id_start) = line.find("trace id ") {
                    let id_part = &line[id_start + 9..];
                    if let Some(id_end) = id_part.find(' ') {
                        trace_id = Some(id_part[..id_end].to_string());

                        // Extract iif (always from first packet match)
                        info.iif = iface.to_string();

                        break;
                    }
                }
            }
        }
    }

    // If we didn't find packet with iif, try matching on oif (for OUTPUT hook packets)
    if trace_id.is_none() {
        for line in trace_content.lines() {
            let ip_matches = line.contains("packet:")
                && line.contains(&format!("oif \"{}\"", iface))
                && ((line.contains(&format!("ip saddr {}", src_ip))
                    && line.contains(&format!("ip daddr {}", dst_ip)))
                    || (line.contains(&format!("ip6 saddr {}", src_ip))
                        && line.contains(&format!("ip6 daddr {}", dst_ip))));

            if ip_matches {
                // Check if ports match (for TCP/UDP)
                let ports_match = if let (Some(sp), Some(dp)) = (src_port, dst_port) {
                    (line.contains(&format!("tcp sport {}", sp))
                        && line.contains(&format!("tcp dport {}", dp)))
                        || (line.contains(&format!("udp sport {}", sp))
                            && line.contains(&format!("udp dport {}", dp)))
                } else {
                    // ICMP or no ports to match
                    line.contains("icmp") || line.contains("icmpv6")
                };

                if ports_match {
                    // Extract trace ID
                    if let Some(id_start) = line.find("trace id ") {
                        let id_part = &line[id_start + 9..];
                        if let Some(id_end) = id_part.find(' ') {
                            trace_id = Some(id_part[..id_end].to_string());
                            info.iif = iface.to_string();
                            break;
                        }
                    }
                }
            }
        }
    }

    // If we didn't find our packet by exact IPs, try matching by source IP + ports (iif)
    // This handles cases where conntrack de-NATs the packet before it reaches filter hooks
    if trace_id.is_none() && src_port.is_some() && dst_port.is_some() {
        for line in trace_content.lines() {
            let ip_matches = line.contains("packet:")
                && line.contains(&format!("iif \"{}\"", iface))
                && (line.contains(&format!("ip saddr {}", src_ip))
                    || line.contains(&format!("ip6 saddr {}", src_ip)));

            if ip_matches {
                let ports_match = if let (Some(sp), Some(dp)) = (src_port, dst_port) {
                    (line.contains(&format!("tcp sport {}", sp))
                        && line.contains(&format!("tcp dport {}", dp)))
                        || (line.contains(&format!("udp sport {}", sp))
                            && line.contains(&format!("udp dport {}", dp)))
                } else {
                    false
                };

                if ports_match {
                    if let Some(id_start) = line.find("trace id ") {
                        let id_part = &line[id_start + 9..];
                        if let Some(id_end) = id_part.find(' ') {
                            trace_id = Some(id_part[..id_end].to_string());
                            info.iif = iface.to_string();
                            break;
                        }
                    }
                }
            }
        }
    }

    // If we still didn't find by iif, try matching by source IP + ports with oif (for OUTPUT hook)
    if trace_id.is_none() && src_port.is_some() && dst_port.is_some() {
        for line in trace_content.lines() {
            let ip_matches = line.contains("packet:")
                && line.contains(&format!("oif \"{}\"", iface))
                && (line.contains(&format!("ip saddr {}", src_ip))
                    || line.contains(&format!("ip6 saddr {}", src_ip)));

            if ip_matches {
                let ports_match = if let (Some(sp), Some(dp)) = (src_port, dst_port) {
                    (line.contains(&format!("tcp sport {}", sp))
                        && line.contains(&format!("tcp dport {}", dp)))
                        || (line.contains(&format!("udp sport {}", sp))
                            && line.contains(&format!("udp dport {}", dp)))
                } else {
                    false
                };

                if ports_match {
                    if let Some(id_start) = line.find("trace id ") {
                        let id_part = &line[id_start + 9..];
                        if let Some(id_end) = id_part.find(' ') {
                            trace_id = Some(id_part[..id_end].to_string());
                            info.iif = iface.to_string();
                            break;
                        }
                    }
                }
            }
        }
    }

    // If we still didn't find our packet, return None
    let trace_id = trace_id?;

    // Second pass: collect all lines with this trace ID to get hooks, verdicts, oif, and NAT
    let mut current_hook: Option<String> = None;

    for line in trace_content.lines() {
        if line.contains(&format!("trace id {}", trace_id)) {
            // Extract hook if this is a packet line
            if line.contains("packet:") {
                // Extract hook from this line (e.g., "trace id XXX inet filter FORWARD packet:")
                // Word indices: 0=trace, 1=id, 2=XXX, 3=inet, 4=filter, 5=FORWARD
                if let Some(hook_match) = line.split_whitespace().nth(5) {
                    current_hook = Some(hook_match.to_uppercase());
                }

                // Extract oif if present (use the most recent one)
                if let Some(oif_start) = line.find("oif \"") {
                    let oif_part = &line[oif_start + 5..];
                    if let Some(oif_end) = oif_part.find('"') {
                        info.oif = Some(oif_part[..oif_end].to_string());
                    }
                }
            }

            // Extract verdict and associate with current hook
            if let Some(ref hook) = current_hook {
                if line.contains("policy accept") || line.contains("(verdict accept)") {
                    info.hook_verdicts
                        .insert(hook.clone(), "accept".to_string());
                } else if line.contains("policy drop") || line.contains("(verdict drop)") {
                    // Check if this is actually a reject rule (nftables shows reject as "(verdict drop)")
                    // The rule text will contain " reject " before "(verdict drop)"
                    if line.contains(" rule ") && line.contains(" reject ") {
                        info.hook_verdicts
                            .insert(hook.clone(), "reject".to_string());
                    } else {
                        info.hook_verdicts.insert(hook.clone(), "drop".to_string());
                    }
                } else if line.contains("policy reject") || line.contains("(verdict reject)") {
                    info.hook_verdicts
                        .insert(hook.clone(), "reject".to_string());
                }
            }

            // Extract SNAT
            if line.contains("snat to ") || line.contains("snat ip to ") {
                let to_start = if let Some(pos) = line.find("snat ip to ") {
                    pos + 11
                } else if let Some(pos) = line.find("snat to ") {
                    pos + 8
                } else {
                    continue;
                };

                let addr_part = &line[to_start..];
                if let Some(addr_end) = addr_part.find(|c: char| c.is_whitespace()) {
                    let addr = &addr_part[..addr_end];
                    // Strip port if present
                    if let Some(colon_pos) = addr.find(':') {
                        info.src_nat = Some(addr[..colon_pos].to_string());
                    } else {
                        info.src_nat = Some(addr.to_string());
                    }
                }
            }

            // Extract DNAT
            if line.contains("dnat to ") || line.contains("dnat ip to ") {
                let to_start = if let Some(pos) = line.find("dnat ip to ") {
                    pos + 11
                } else if let Some(pos) = line.find("dnat to ") {
                    pos + 8
                } else {
                    continue;
                };

                let addr_part = &line[to_start..];
                if let Some(addr_end) = addr_part.find(|c: char| c.is_whitespace()) {
                    let addr = &addr_part[..addr_end];
                    // Strip port if present
                    if let Some(colon_pos) = addr.find(':') {
                        info.dst_nat = Some(addr[..colon_pos].to_string());
                    } else {
                        info.dst_nat = Some(addr.to_string());
                    }
                }
            }

            // Extract masquerade (resolve to interface IP)
            if line.contains("masquerade") && info.src_nat.is_none() {
                // Primary: Use oif from packet line (most reliable, set when we saw the packet)
                let oif_name = if let Some(ref oif) = info.oif {
                    Some(oif.clone())
                } else {
                    // Fallback: Extract from rule line if it's a positive match (not != or @)
                    // This handles edge cases where packet line might not have oif
                    if let Some(oifname_start) = line.find("oifname \"") {
                        // Check it's not a negative match
                        let before_oifname = &line[..oifname_start];
                        if !before_oifname.ends_with("!= ") && !before_oifname.ends_with("@ ") {
                            let oif_part = &line[oifname_start + 9..];
                            if let Some(oif_end) = oif_part.find('"') {
                                Some(oif_part[..oif_end].to_string())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if let Some(oif_name) = oif_name {
                    if let Some(oif_ip) = iface_ips.get(&oif_name) {
                        // Strip CIDR notation (e.g., "203.0.113.10/24" -> "203.0.113.10")
                        let ip_only = oif_ip.split('/').next().unwrap_or(oif_ip);
                        info.src_nat = Some(ip_only.to_string());
                    }
                }
            }
        }
    }

    Some(info)
}
