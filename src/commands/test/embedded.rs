use crate::config::{
    Expectation, GuestSetup, Icmp, Interface, Network, Packet, PacketStep, Route, SimConfig, Tcp,
    TestCase, Transport, Udp, Verdict,
};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;

/// build a test suite from `# !` directive comments in a ruleset, so a
/// ruleset can carry its own tests without a separate TOML file
pub fn parse_embedded_tests(nft_content: &str) -> Result<SimConfig> {
    let mut interfaces = Vec::new();
    let mut routes = Vec::new();
    let mut test_cases = Vec::new();
    let mut sysctls = HashMap::new();
    let mut pre_nft_commands = Vec::new();
    let mut post_nft_commands = Vec::new();
    let mut current_test: Option<TestCase> = None;

    for (line_num, line) in nft_content.lines().enumerate() {
        let line = line.trim();

        if line_num == 0 && line.starts_with("#!") {
            continue;
        }

        if !line.starts_with("#") {
            continue;
        }
        
        let comment_content = line.trim_start_matches('#').trim();
        if !comment_content.starts_with("!") {
            continue;
        }

        let directive = comment_content.trim_start_matches('!').trim();
        if directive.is_empty() {
            continue;
        }

        let tokens = tokenize(directive)?;
        if tokens.is_empty() {
            continue;
        }

        let mut parser = TokenParser::new(tokens);
        let command = parser.next().unwrap();

        match command.as_str() {
            "setup" => {
                let subcommand = parser.next().context(format!("line {}: setup missing subcommand", line_num + 1))?;
                match subcommand.as_str() {
                    "interface" => {
                        let name = parser.next().context(format!("line {}: missing interface name", line_num + 1))?;
                        let mut ips = vec![parser.next().context(format!("line {}: missing interface IP", line_num + 1))?];
                        ips.extend(std::iter::from_fn(|| parser.next()));
                        interfaces.push(Interface { name, ips });
                    }
                    "route" => {
                        let destination = parser.next().context(format!("line {}: missing route destination", line_num + 1))?;
                        parser.expect("via")?;
                        let via = parser.next().context(format!("line {}: missing route gateway", line_num + 1))?;
                        routes.push(Route { destination, via });
                    }
                    "sysctl" => {
                        let kv = parser.next().context(format!("line {}: missing sysctl key=value", line_num + 1))?;
                        if let Some((k, v)) = kv.split_once('=') {
                            sysctls.insert(k.to_string(), v.to_string());
                        } else {
                            bail!("line {}: invalid sysctl format '{}' (expected key=value)", line_num + 1, kv);
                        }
                    }
                    "pre_cmd" => {
                        let cmd = parser.next().context(format!("line {}: missing command string", line_num + 1))?;
                        pre_nft_commands.push(cmd);
                    }
                    "post_cmd" => {
                        let cmd = parser.next().context(format!("line {}: missing command string", line_num + 1))?;
                        post_nft_commands.push(cmd);
                    }
                    _ => bail!("line {}: unknown setup command '{}'", line_num + 1, subcommand),
                }
            }
            "test" => {
                if let Some(test) = current_test.take() {
                    test_cases.push(test);
                }
                let name = parser.next().context(format!("line {}: missing test name", line_num + 1))?;
                current_test = Some(TestCase {
                    name,
                    packets: Vec::new(),
                });
            }
            "inject" => {
                if let Some(ref mut test) = current_test {
                    let iface = parser.next().context(format!("line {}: missing interface", line_num + 1))?;

                    let mut saddr = "0.0.0.0".to_string();
                    let mut daddr = "0.0.0.0".to_string();
                    let mut transport: Option<Transport> = None;

                    while let Some(token) = parser.peek() {
                        match token.as_str() {
                            "ip" => {
                                parser.next();
                                while let Some(sub) = parser.peek() {
                                    match sub.as_str() {
                                        "saddr" => { parser.next(); saddr = parser.next().context("missing saddr")?; }
                                        "daddr" => { parser.next(); daddr = parser.next().context("missing daddr")?; }
                                        _ => break,
                                    }
                                }
                            }
                            "tcp" => {
                                parser.next();
                                let mut sport = 0;
                                let mut dport = 0;
                                let mut flags = Vec::new();
                                
                                while let Some(sub) = parser.peek() {
                                    match sub.as_str() {
                                        "sport" => { parser.next(); sport = parser.parse_u16()?; }
                                        "dport" => { parser.next(); dport = parser.parse_u16()?; }
                                        "flags" => { 
                                            parser.next(); 
                                            let flag_str = parser.next().context("missing flags")?;
                                            flags = flag_str.split(',').map(|s| s.to_string()).collect();
                                        }
                                        _ => break,
                                    }
                                }
                                transport = Some(Transport::Tcp(Tcp { source_port: sport, dest_port: dport, flags, payload: None }));
                            }
                            "udp" => {
                                parser.next();
                                let mut sport = 0;
                                let mut dport = 0;
                                
                                while let Some(sub) = parser.peek() {
                                    match sub.as_str() {
                                        "sport" => { parser.next(); sport = parser.parse_u16()?; }
                                        "dport" => { parser.next(); dport = parser.parse_u16()?; }
                                        _ => break,
                                    }
                                }
                                transport = Some(Transport::Udp(Udp { source_port: sport, dest_port: dport, payload: None }));
                            }
                            "icmp" => {
                                parser.next();
                                let mut icmp_type = 8; // default echo-request
                                let mut code = 0;
                                
                                while let Some(sub) = parser.peek() {
                                    match sub.as_str() {
                                        "type" => { 
                                            parser.next(); 
                                            let t = parser.next().context("missing icmp type")?;
                                            icmp_type = parse_icmp_type(&t).ok_or_else(|| anyhow::anyhow!("unknown ICMP type: {}", t))?;
                                        }
                                        "code" => { parser.next(); code = parser.parse_u8()?; }
                                        _ => break,
                                    }
                                }
                                transport = Some(Transport::Icmp(Icmp { icmp_type, code, payload: None }));
                            }
                            "payload" => {
                                // TODO: payload parsing if needed later
                                parser.next();
                                parser.next();
                            }
                            _ => {
                                bail!("line {}: unexpected token '{}' in inject command", line_num + 1, token);
                            }
                        }
                    }

                    let transport = transport.context(format!("line {}: missing protocol definition (tcp/udp/icmp)", line_num + 1))?;

                    test.packets.push(PacketStep {
                        packet: Packet {
                            on_interface: iface,
                            source_ip: saddr,
                            dest_ip: daddr,
                            transport,
                        },
                        expect: Vec::new(),
                    });
                } else {
                    bail!("line {}: inject command outside of test block", line_num + 1);
                }
            }
            "expect" => {
                if let Some(ref mut test) = current_test {
                    if let Some(last_step) = test.packets.last_mut() {
                        let verdict_str = parser.next().context(format!("line {}: missing verdict", line_num + 1))?;
                        let verdict = match verdict_str.to_lowercase().as_str() {
                            "accept" => Verdict::Accept,
                            "drop" => Verdict::Drop,
                            "reject" => Verdict::Reject,
                            _ => bail!("line {}: invalid verdict '{}'", line_num + 1, verdict_str),
                        };

                        let mut oif = None;
                        let mut snat = None;
                        let mut dnat = None;

                        while let Some(token) = parser.peek() {
                            match token.as_str() {
                                "oif" => { parser.next(); oif = Some(parser.next().context("missing oif")?); }
                                "snat" => { parser.next(); snat = Some(parser.next().context("missing snat IP")?); }
                                "dnat" => { parser.next(); dnat = Some(parser.next().context("missing dnat IP")?); }
                                _ => break,
                            }
                        }

                        last_step.expect.push(Expectation {
                            verdict,
                            hook: None,
                            to_interface: oif,
                            src_nat: snat,
                            dst_nat: dnat,
                        });
                    } else {
                        bail!("line {}: expect command without preceding inject", line_num + 1);
                    }
                } else {
                    bail!("line {}: expect command outside of test block", line_num + 1);
                }
            }
            _ => bail!("line {}: unknown command '{}'", line_num + 1, command),
        }
    }

    if let Some(test) = current_test {
        test_cases.push(test);
    }

    Ok(SimConfig {
        ruleset: None,
        network: Network {
            interfaces,
            routes,
        },
        guest_setup: GuestSetup {
            sysctls,
            pre_nft_commands,
            post_nft_commands,
        },
        test_cases,
    })
}

/// token stream with one token of lookahead
struct TokenParser {
    tokens: std::vec::IntoIter<String>,
    peeked: Option<String>,
}

impl TokenParser {
    fn new(tokens: Vec<String>) -> Self {
        Self {
            tokens: tokens.into_iter(),
            peeked: None,
        }
    }

    fn next(&mut self) -> Option<String> {
        if let Some(v) = self.peeked.take() {
            Some(v)
        } else {
            self.tokens.next()
        }
    }

    fn peek(&mut self) -> Option<&String> {
        if self.peeked.is_none() {
            self.peeked = self.tokens.next();
        }
        self.peeked.as_ref()
    }

    /// consume the next token, failing unless it is `expected`
    fn expect(&mut self, expected: &str) -> Result<()> {
        let got = self.next().context("unexpected end of line")?;
        if got != expected {
            bail!("expected '{}', got '{}'", expected, got);
        }
        Ok(())
    }

    /// consume the next token as a u16
    fn parse_u16(&mut self) -> Result<u16> {
        let s = self.next().context("missing integer value")?;
        s.parse::<u16>().with_context(|| format!("invalid u16: {}", s))
    }

    /// consume the next token as a u8
    fn parse_u8(&mut self) -> Result<u8> {
        let s = self.next().context("missing integer value")?;
        s.parse::<u8>().with_context(|| format!("invalid u8: {}", s))
    }
}

/// split a directive on whitespace, keeping double-quoted strings as one token
fn tokenize(input: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut current = String::new();
    let mut in_quote = false;

    while let Some(c) = chars.next() {
        if in_quote {
            if c == '"' {
                in_quote = false;
                tokens.push(current.clone());
                current.clear();
            } else {
                current.push(c);
            }
        } else {
            if c == '"' {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                in_quote = true;
            } else if c.is_whitespace() {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            } else {
                current.push(c);
            }
        }
    }
    
    if in_quote {
        bail!("unterminated string literal");
    }
    
    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

/// resolve an ICMP type given as a number or a common nftables type name
fn parse_icmp_type(s: &str) -> Option<u8> {
    if let Ok(v) = s.parse::<u8>() {
        return Some(v);
    }
    match s {
        "echo-reply" => Some(0),
        "echo-request" => Some(8),
        "destination-unreachable" => Some(3),
        "redirect" => Some(5),
        "time-exceeded" => Some(11),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gateway_embedded() {
        let content = r#"
# ! setup interface eth0 192.168.1.1
# ! setup interface eth1 10.0.0.1
# ! setup sysctl net.ipv4.ip_forward=1

# ! test "outbound HTTP (accepted & SNAT)"
# ! inject eth0 ip saddr 192.168.1.100 daddr 8.8.8.8 tcp sport 54321 dport 80 flags syn
# ! expect accept oif eth1 snat 10.0.0.1

# ! test "inbound SSH (dropped)"
# ! inject eth1 ip saddr 8.8.8.8 daddr 10.0.0.1 tcp sport 12345 dport 22 flags syn
# ! expect drop

# ! test "internal ICMP (accepted)"
# ! inject eth0 ip saddr 192.168.1.100 daddr 192.168.1.1 icmp type echo-request
# ! expect accept
"#;
        let config = parse_embedded_tests(content).expect("failed to parse embedded tests");
        assert_eq!(config.network.interfaces.len(), 2);
        assert_eq!(config.guest_setup.sysctls.len(), 1);
        assert_eq!(config.test_cases.len(), 3);
        
        let t1 = &config.test_cases[0];
        assert_eq!(t1.name, "outbound HTTP (accepted & SNAT)");
        assert_eq!(t1.packets.len(), 1);
        assert_eq!(t1.packets[0].packet.on_interface, "eth0");
        assert_eq!(t1.packets[0].expect[0].to_interface.as_deref(), Some("eth1"));
    }
}
