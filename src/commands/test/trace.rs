// parses `nft monitor trace` output to extract verdicts, hooks, and NAT information

use crate::config::{is_ipv6, same_address};
use std::collections::HashMap;

const TRACE_FAMILIES: &[&str] = &["ip", "ip6", "inet", "arp", "bridge", "netdev"];
const TRACE_VERDICTS: &[&str] = &[
    "accept", "drop", "continue", "return", "jump", "goto", "stolen", "queue", "repeat", "stop",
];

/// check that a single non-empty line matches nft monitor trace's envelope format
fn is_recognized_trace_line(line: &str) -> bool {
    let line = line.trim_end();
    let Some(rest) = line.strip_prefix("trace id ") else {
        return false;
    };
    let mut parts = rest.splitn(6, ' ');
    let (Some(id), Some(family), Some(table), Some(chain), Some(kind), Some(body)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    if id.is_empty()
        || !id.chars().all(|c| c.is_ascii_hexdigit())
        || !TRACE_FAMILIES.contains(&family)
        || table.is_empty()
        || chain.is_empty()
    {
        return false;
    }
    match kind {
        "packet:" => !body.is_empty(),
        "policy" => matches!(body.split_whitespace().next(), Some("accept" | "drop")),
        "verdict" => body
            .split_whitespace()
            .next()
            .is_some_and(|v| TRACE_VERDICTS.contains(&v)),
        "rule" => {
            let Some((_, verdict_tail)) = body.rsplit_once("(verdict ") else {
                return false;
            };
            let Some(verdict_expr) = verdict_tail.strip_suffix(')') else {
                return false;
            };
            verdict_expr
                .split_whitespace()
                .next()
                .is_some_and(|v| TRACE_VERDICTS.contains(&v))
        }
        _ => false,
    }
}

/// return every non-empty line in `trace` that does not match nft trace format
pub(super) fn find_unrecognized_trace_lines(trace: &str) -> Vec<&str> {
    trace
        .lines()
        .filter(|line| !line.trim().is_empty() && !is_recognized_trace_line(line))
        .collect()
}

/// extract the target IP address from a `snat` or `dnat` rule trace line
fn extract_nat_addr(line: &str, kind: &str) -> Option<String> {
    let patterns = [
        format!("{} ip6 to ", kind),
        format!("{} ip to ", kind),
        format!("{} to ", kind),
    ];
    let after = patterns
        .iter()
        .find_map(|pat| line.find(pat).map(|pos| &line[pos + pat.len()..]))?;
    let token = after.split_whitespace().next()?;
    if let Some(bracketed) = token.strip_prefix('[') {
        bracketed.split(']').next().map(str::to_string)
    } else if token.matches(':').count() == 1 {
        token.split(':').next().map(str::to_string)
    } else {
        Some(token.to_string())
    }
}

/// hook of each base chain in the loaded ruleset, keyed "family table chain"
/// (e.g. "ip wg-quick-wg0 preraw" -> "PREROUTING")
pub(super) type ChainHooks = HashMap<String, String>;

/// parse `nft -j list chains` output into the hook of each base chain
pub(super) fn parse_chain_hooks(json: &str) -> ChainHooks {
    let value: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    value["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let chain = &entry["chain"];
            let hook = chain["hook"].as_str()?;
            let key = format!(
                "{} {} {}",
                chain["family"].as_str()?,
                chain["table"].as_str()?,
                chain["name"].as_str()?
            );
            Some((key, hook.to_uppercase()))
        })
        .collect()
}

/// parsed trace information for a packet
#[derive(Debug, Clone)]
pub(super) struct TraceInfo {
    pub hook_verdicts: HashMap<String, String>, // hook -> verdict (e.g., "FORWARD" -> "accept")
    pub oif: Option<String>,                    // output interface (for forwarded packets)
    pub src_nat: Option<String>,                // SNAT address
    pub dst_nat: Option<String>,                // DNAT address
    pub masquerade: bool,                       // src_nat is only a guess until conntrack confirms it
}

/// find the source address the kernel translated a connection to: the
/// conntrack entry whose original tuple matches the packet lists the reply
/// tuple next, and the reply's destination is the translated source
pub(super) fn parse_conntrack_snat(
    table: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Option<String> {
    table.lines().find_map(|line| {
        let fields = |key: &str| -> Vec<&str> {
            line.split_whitespace().filter_map(|f| f.strip_prefix(key)).collect()
        };
        let (srcs, dsts) = (fields("src="), fields("dst="));
        let (sports, dports) = (fields("sport="), fields("dport="));
        let port_matches = |want: Option<u16>, got: &[&str]| {
            want.is_none_or(|p| got.first() == Some(&p.to_string().as_str()))
        };
        let matches = srcs.len() == 2
            && dsts.len() == 2
            && same_address(srcs[0], src_ip)
            && same_address(dsts[0], dst_ip)
            && port_matches(src_port, &sports)
            && port_matches(dst_port, &dports);
        // canonical form keeps failure messages readable
        matches.then(|| dsts[1].parse::<std::net::IpAddr>().map_or(dsts[1].to_string(), |a| a.to_string()))
    })
}

/// the trace ID of the first packet line on `iface` (as its `direction`, iif
/// or oif) that matches the packet. a strict match also needs the destination
/// address, and matches ICMP when there are no ports; a loose match needs
/// ports, since source address and ports alone must identify the connection
fn find_trace_id(
    trace: &str,
    direction: &str,
    iface: &str,
    src_ip: &str,
    dst_ip: &str,
    ports: Option<(u16, u16)>,
    strict: bool,
) -> Option<String> {
    let on_iface = format!("{} \"{}\"", direction, iface);
    let addrs_match = |line: &str| {
        ["ip", "ip6"].iter().any(|family| {
            line.contains(&format!("{} saddr {}", family, src_ip))
                && (!strict || line.contains(&format!("{} daddr {}", family, dst_ip)))
        })
    };
    let ports_match = |line: &str| match ports {
        Some((sp, dp)) => ["tcp", "udp"].iter().any(|proto| {
            line.contains(&format!("{} sport {}", proto, sp))
                && line.contains(&format!("{} dport {}", proto, dp))
        }),
        None => strict && line.contains("icmp"),
    };
    trace
        .lines()
        .filter(|line| line.contains("packet:") && line.contains(&on_iface))
        .filter(|line| addrs_match(line) && ports_match(line))
        .find_map(|line| line.split("trace id ").nth(1)?.split(' ').next().map(str::to_string))
}

/// find a specific packet in the trace and extract its routing and verdict
/// information, or None if the packet is not in the trace
pub(super) fn parse_trace_for_packet(
    trace_content: &str,
    iface: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    iface_ips: &HashMap<String, Vec<String>>,
    chain_hooks: &ChainHooks,
) -> Option<TraceInfo> {
    // first pass: find the packet's trace ID. iif matches the common case and
    // oif the OUTPUT hook; when neither matches in full, conntrack may have
    // de-NATed the packet before the filter hooks, so match source and ports
    let ports = src_port.zip(dst_port);
    let trace_id = [("iif", true), ("oif", true), ("iif", false), ("oif", false)]
        .into_iter()
        .find_map(|(direction, strict)| {
            find_trace_id(trace_content, direction, iface, src_ip, dst_ip, ports, strict)
        })?;
    let mut info = TraceInfo {
        hook_verdicts: HashMap::new(),
        oif: None,
        src_nat: None,
        dst_nat: None,
        masquerade: false,
    };

    // second pass: collect hooks, verdicts, oif, and NAT from every line with this trace ID
    let mut current_hook: Option<String> = None;

    for line in trace_content.lines() {
        if line.contains(&format!("trace id {}", trace_id)) {
            if line.contains("packet:") {
                // e.g. "trace id XXX inet filter FORWARD packet:", where words
                // 3..6 are family, table and chain. a base chain resolves to its hook; without the ruleset's hooks the
                // chain name stands in for it
                let words: Vec<&str> = line.split_whitespace().collect();
                if let Some(chain) = words.get(5) {
                    let key = words[3..6].join(" ");
                    current_hook = Some(
                        chain_hooks
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| chain.to_uppercase()),
                    );
                }

                // the most recent oif wins
                if let Some(oif_start) = line.find("oif \"") {
                    let oif_part = &line[oif_start + 5..];
                    if let Some(oif_end) = oif_part.find('"') {
                        info.oif = Some(oif_part[..oif_end].to_string());
                    }
                }
            }

            if let Some(ref hook) = current_hook {
                if line.contains("policy accept") || line.contains("(verdict accept)") {
                    info.hook_verdicts
                        .insert(hook.clone(), "accept".to_string());
                } else if line.contains("policy drop") || line.contains("(verdict drop)") {
                    // nftables traces a reject rule as "(verdict drop)", so
                    // look for " reject " in the rule text
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

            if let Some(addr) = extract_nat_addr(line, "snat") {
                info.src_nat = Some(addr);
            }

            if let Some(addr) = extract_nat_addr(line, "dnat") {
                info.dst_nat = Some(addr);
            }

            // masquerade traces carry no address, so guess the output
            // interface's first address of the packet's family (the kernel
            // keeps the family when it translates), preferring the packet
            // line's oif; the runner replaces the guess with conntrack's answer
            if line.contains("masquerade") && info.src_nat.is_none() {
                info.masquerade = true;
                let oif_name = if let Some(ref oif) = info.oif {
                    Some(oif.clone())
                } else {
                    // fall back to a positive oifname match in the rule (not != or @)
                    if let Some(oifname_start) = line.find("oifname \"") {
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

                info.src_nat = oif_name
                    .and_then(|name| iface_ips.get(&name))
                    .and_then(|ips| ips.iter().find(|ip| is_ipv6(ip) == is_ipv6(src_ip)))
                    .cloned();
            }
        }
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    // a base chain named for its owner (wg-quick's preraw) rather than its hook
    const PRERAW_TRACE: &str = "\
trace id 1a2b3c4d ip wg-quick-wg0 preraw packet: iif \"br0\" ip saddr 10.1.100.52 ip daddr 10.1.200.10 ip protocol tcp tcp sport 40006 tcp dport 22 tcp flags == syn
trace id 1a2b3c4d ip wg-quick-wg0 preraw rule iifname != \"wg0\" ip daddr 10.1.200.10 drop (verdict drop)
";

    const CHAINS_JSON: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.6", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "wg-quick-wg0", "name": "preraw", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -300, "policy": "accept"}}, {"chain": {"family": "inet", "table": "filter", "name": "DOCKER", "handle": 2}}]}"#;

    fn parse(trace: &str, chain_hooks: &ChainHooks) -> TraceInfo {
        parse_trace_for_packet(trace, "br0", "10.1.100.52", "10.1.200.10", Some(40006), Some(22), &HashMap::new(), chain_hooks)
            .expect("packet not found in trace")
    }

    #[test]
    fn chain_hooks_map_base_chains_only() {
        let hooks = parse_chain_hooks(CHAINS_JSON);
        assert_eq!(hooks.get("ip wg-quick-wg0 preraw").map(String::as_str), Some("PREROUTING"));
        assert!(!hooks.contains_key("inet filter DOCKER"));
    }

    #[test]
    fn verdict_is_reported_on_the_chains_hook() {
        let info = parse(PRERAW_TRACE, &parse_chain_hooks(CHAINS_JSON));
        assert_eq!(info.hook_verdicts.get("PREROUTING").map(String::as_str), Some("drop"));
    }

    #[test]
    fn chain_name_is_the_hook_when_hooks_are_unknown() {
        let info = parse(PRERAW_TRACE, &ChainHooks::new());
        assert_eq!(info.hook_verdicts.get("PRERAW").map(String::as_str), Some("drop"));
    }

    const OUTPUT_ICMP_TRACE: &str = "\
trace id 5e6f7a8b inet filter output packet: oif \"eth0\" ip saddr 192.0.2.1 ip daddr 198.51.100.7 ip protocol icmp icmp type echo-request
trace id 5e6f7a8b inet filter output policy accept
";

    // the reply to a DNATed connection: the filter hook sees the de-NATed
    // destination, so only the source address and ports identify it
    const DENAT_TRACE: &str = "\
trace id 9c0d1e2f inet filter forward packet: iif \"eth1\" oif \"eth0\" ip saddr 10.0.0.5 ip daddr 192.168.1.50 ip protocol tcp tcp sport 8080 tcp dport 40000 tcp flags == syn | ack
trace id 9c0d1e2f inet filter forward policy accept
";

    #[test]
    fn output_packet_is_found_by_oif_without_ports() {
        let info = parse_trace_for_packet(OUTPUT_ICMP_TRACE, "eth0", "192.0.2.1", "198.51.100.7", None, None, &HashMap::new(), &ChainHooks::new())
            .expect("packet not found in trace");
        assert_eq!(info.hook_verdicts.get("OUTPUT").map(String::as_str), Some("accept"));
    }

    #[test]
    fn denat_reply_is_found_by_source_and_ports() {
        let found = |dst, ports: Option<(u16, u16)>| {
            parse_trace_for_packet(DENAT_TRACE, "eth1", "10.0.0.5", dst, ports.map(|p| p.0), ports.map(|p| p.1), &HashMap::new(), &ChainHooks::new())
                .is_some()
        };
        assert!(found("203.0.113.10", Some((8080, 40000))));
        assert!(!found("203.0.113.10", None), "the loose match needs ports");
    }

    // /proc/net/nf_conntrack lines: original tuple, then the reply tuple
    const CONNTRACK: &str = "\
ipv4     2 tcp      6 118 SYN_SENT src=192.168.1.50 dst=192.0.2.7 sport=40000 dport=443 [UNREPLIED] src=192.0.2.7 dst=203.0.113.10 sport=443 dport=40000 mark=0 zone=0 use=2
ipv6     10 tcp      6 118 SYN_SENT src=2001:db8:2::50 dst=2001:db8:ffff::7 sport=40001 dport=443 [UNREPLIED] src=2001:db8:ffff::7 dst=2001:db8:1::10 sport=443 dport=40001 mark=0 zone=0 use=2
ipv4     2 icmp     1 29 src=192.168.1.51 dst=192.0.2.7 type=8 code=0 id=1 [UNREPLIED] src=192.0.2.7 dst=198.51.100.10 type=0 code=0 id=1 mark=0 zone=0 use=2
";

    #[test]
    fn conntrack_reply_destination_is_the_translated_source() {
        assert_eq!(
            parse_conntrack_snat(CONNTRACK, "192.168.1.50", "192.0.2.7", Some(40000), Some(443)).as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(
            parse_conntrack_snat(CONNTRACK, "192.168.1.51", "192.0.2.7", None, None).as_deref(),
            Some("198.51.100.10")
        );
    }

    #[test]
    fn conntrack_matches_ipv6_in_any_spelling() {
        assert_eq!(
            parse_conntrack_snat(CONNTRACK, "2001:db8:2:0::50", "2001:db8:ffff::7", Some(40001), Some(443)).as_deref(),
            Some("2001:db8:1::10")
        );
    }

    #[test]
    fn conntrack_without_the_connection_has_no_answer() {
        assert_eq!(parse_conntrack_snat(CONNTRACK, "192.168.1.50", "192.0.2.7", Some(40009), Some(443)), None);
    }

    #[test]
    fn recognized_trace_envelopes_produce_no_errors() {
        let valid = "\
trace id 69d642c1 inet filter prerouting packet: iif \"eth0\" ip saddr 192.168.1.50 ip daddr 8.8.8.8
trace id 69d642c1 inet filter prerouting rule meta nftrace set 1 (verdict continue)
trace id 69d642c1 inet filter prerouting rule tcp dport 22 jump ssh_in (verdict jump ssh_in)
trace id 69d642c1 inet filter ssh_in verdict return
trace id 69d642c1 inet filter prerouting policy accept meta mark 0x000000d4 
";
        assert!(find_unrecognized_trace_lines(valid).is_empty());
    }

    #[test]
    fn unrecognized_trace_lines_are_reported() {
        let mixed = "\
trace id 69d642c1 inet filter forward policy drop
unexpected nft output v999
trace id 69d642c1 inet filter forward rule tcp dport 80 (verdict bogus)
";
        assert_eq!(
            find_unrecognized_trace_lines(mixed),
            vec![
                "unexpected nft output v999",
                "trace id 69d642c1 inet filter forward rule tcp dport 80 (verdict bogus)",
            ]
        );
    }

    #[test]
    fn ipv6_nat_addresses_preserve_full_address() {
        let trace = "\
trace id 1234abcd ip6 nat prerouting packet: iif \"eth1\" ip6 saddr 2001:db8:1::2 ip6 daddr 2001:db8:2::1 ip6 nexthdr tcp tcp sport 40000 tcp dport 443
trace id 1234abcd ip6 nat prerouting rule tcp dport 443 dnat ip6 to [2001:db8:3::10]:8443 (verdict accept)
trace id 1234abcd ip6 nat postrouting packet: iif \"eth1\" oif \"eth0\" ip6 saddr 2001:db8:1::2 ip6 daddr 2001:db8:3::10 ip6 nexthdr tcp tcp sport 40000 tcp dport 8443
trace id 1234abcd ip6 nat postrouting rule oifname \"eth0\" snat ip6 to 2001:db8:3::1 (verdict accept)
";
        let info = parse_trace_for_packet(trace, "eth1", "2001:db8:1::2", "2001:db8:2::1", Some(40000), Some(443), &HashMap::new(), &ChainHooks::new())
            .expect("packet not found in trace");
        assert_eq!(info.dst_nat.as_deref(), Some("2001:db8:3::10"));
        assert_eq!(info.src_nat.as_deref(), Some("2001:db8:3::1"));
    }
}
