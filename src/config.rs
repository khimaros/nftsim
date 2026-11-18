use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SimConfig {
    /// ruleset under test, relative to this file, so `nftsim test suite.toml`
    /// needs no ruleset argument
    #[serde(default)]
    pub ruleset: Option<std::path::PathBuf>,
    pub network: Network,
    #[serde(default)]
    pub guest_setup: GuestSetup,
    #[serde(rename = "tests")]
    pub test_cases: Vec<TestCase>,
}

impl SimConfig {
    /// the suite's own ruleset, resolved against the directory of its file
    pub fn ruleset_path(&self, config_path: &std::path::Path) -> Option<std::path::PathBuf> {
        let ruleset = self.ruleset.as_ref()?;
        Some(config_path.parent().unwrap_or(std::path::Path::new("")).join(ruleset))
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// a guest interface and every address it carries; real hosts are dual-stack,
/// so `ips` holds any number of addresses and `ip` stays as a shorthand
#[derive(Debug, Deserialize, Clone)]
#[serde(try_from = "RawInterface")]
pub struct Interface {
    pub name: String,
    pub ips: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterface {
    name: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    ips: Vec<String>,
}

impl TryFrom<RawInterface> for Interface {
    type Error = String;

    fn try_from(raw: RawInterface) -> Result<Self, Self::Error> {
        let ips: Vec<String> = raw.ip.into_iter().chain(raw.ips).collect();
        if ips.is_empty() {
            return Err(format!("interface {} needs `ip` or `ips`", raw.name));
        }
        Ok(Interface { name: raw.name, ips })
    }
}

impl Interface {
    /// configured addresses without their prefix length
    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        self.ips.iter().map(|ip| ip.split('/').next().unwrap_or(ip))
    }
}

/// true for IPv6 addresses, which always contain a colon
pub fn is_ipv6(addr: &str) -> bool {
    addr.contains(':')
}

/// compare two addresses by value, since one IPv6 address has many spellings
/// (the kernel prints them expanded, test configs usually compress them)
pub fn same_address(a: &str, b: &str) -> bool {
    match (a.parse::<std::net::IpAddr>(), b.parse::<std::net::IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub destination: String,
    pub via: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct GuestSetup {
    #[serde(default)]
    pub sysctls: HashMap<String, String>,
    #[serde(default)]
    pub pre_nft_commands: Vec<String>,
    #[serde(default)]
    pub post_nft_commands: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    pub name: String,
    pub packets: Vec<PacketStep>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PacketStep {
    pub packet: Packet,
    #[serde(default)]
    pub expect: Vec<Expectation>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub on_interface: String,
    pub source_ip: String,
    pub dest_ip: String,
    #[serde(flatten)]
    pub transport: Transport,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub enum Transport {
    #[serde(rename = "tcp")]
    Tcp(Tcp),
    #[serde(rename = "udp")]
    Udp(Udp),
    #[serde(rename = "icmp")]
    Icmp(Icmp),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Tcp {
    #[serde(deserialize_with = "deserialize_port")]
    pub source_port: u16,
    #[serde(deserialize_with = "deserialize_port")]
    pub dest_port: u16,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Udp {
    #[serde(deserialize_with = "deserialize_port")]
    pub source_port: u16,
    #[serde(deserialize_with = "deserialize_port")]
    pub dest_port: u16,
    #[serde(default)]
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Icmp {
    #[serde(rename = "type", deserialize_with = "deserialize_icmp_type")]
    pub icmp_type: u8,
    pub code: u8,
    #[serde(default)]
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// the nftables verdict (accept, drop, reject)
    #[serde(deserialize_with = "deserialize_lowercase_verdict")]
    pub verdict: Verdict,

    /// which nftables hook processes this packet (prerouting, input, forward, output, postrouting).
    /// when unset, it is forward if to_interface is set and input otherwise
    #[serde(default)]
    pub hook: Option<String>,

    /// for forwarded packets: which interface the packet exits on.
    /// setting this implies hook = "forward"
    #[serde(default)]
    pub to_interface: Option<String>,

    /// expected source NAT address (checked at postrouting)
    #[serde(default)]
    pub src_nat: Option<String>,

    /// expected destination NAT address (checked at prerouting)
    #[serde(default)]
    pub dst_nat: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SUITE: &str = "[network]\n[[tests]]\nname = \"t\"\npackets = []\n";

    #[test]
    fn suite_names_its_ruleset_relative_to_itself() {
        let config: SimConfig = toml::from_str(&format!("ruleset = \"../etc/nftables.conf\"\n{}", SUITE)).unwrap();
        assert_eq!(
            config.ruleset_path(Path::new("/repo/tests/host.toml")),
            Some(Path::new("/repo/tests/../etc/nftables.conf").to_path_buf())
        );
    }

    #[test]
    fn interface_merges_ip_shorthand_with_ips() {
        let iface: Interface = toml::from_str("name = \"eth0\"\nip = \"192.0.2.1/24\"\nips = [\"2001:db8::1/64\"]").unwrap();
        assert_eq!(iface.ips, ["192.0.2.1/24", "2001:db8::1/64"]);
        assert_eq!(iface.addresses().collect::<Vec<_>>(), ["192.0.2.1", "2001:db8::1"]);
    }

    #[test]
    fn interface_without_address_is_rejected() {
        let err = toml::from_str::<Interface>("name = \"eth0\"").unwrap_err();
        assert!(err.to_string().contains("interface eth0 needs `ip` or `ips`"), "{}", err);
    }

    #[test]
    fn suite_without_ruleset_has_none() {
        let config: SimConfig = toml::from_str(SUITE).unwrap();
        assert_eq!(config.ruleset_path(Path::new("/repo/tests/host.toml")), None);
    }
}

/// accept a verdict name in any letter case
fn deserialize_lowercase_verdict<'de, D>(deserializer: D) -> Result<Verdict, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?.to_lowercase();
    match s.as_str() {
        "accept" => Ok(Verdict::Accept),
        "drop" => Ok(Verdict::Drop),
        "reject" => Ok(Verdict::Reject),
        _ => Err(serde::de::Error::unknown_variant(
            &s,
            &["accept", "drop", "reject"],
        )),
    }
}

/// accept a port as a number or as a service name from /etc/services
fn deserialize_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::ffi::CString;
    use std::fmt;

    struct PortVisitor;

    impl<'de> Visitor<'de> for PortVisitor {
        type Value = u16;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a port number or service name (e.g., 'http', 'ssh')")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value <= 65535 {
                Ok(value as u16)
            } else {
                Err(E::custom(format!("port out of range: {}", value)))
            }
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if (0..=65535).contains(&value) {
                Ok(value as u16)
            } else {
                Err(E::custom(format!("port out of range: {}", value)))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            unsafe {
                let service_cstr = CString::new(value)
                    .map_err(|_| E::custom(format!("invalid service name: {}", value)))?;
                let result = libc::getservbyname(service_cstr.as_ptr(), std::ptr::null());
                if !result.is_null() {
                    let port = u16::from_be((*result).s_port as u16);
                    return Ok(port);
                }
            }

            Err(E::custom(format!(
                "unknown service name '{}' (use numeric port or service name from /etc/services)",
                value
            )))
        }
    }

    deserializer.deserialize_any(PortVisitor)
}

/// accept an ICMP type as a number or as an nftables ICMP/ICMPv6 type name
fn deserialize_icmp_type<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct IcmpTypeVisitor;

    impl<'de> Visitor<'de> for IcmpTypeVisitor {
        type Value = u8;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter
                .write_str("an integer 0-255 or nftables ICMP type name (e.g., 'echo-request')")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value <= 255 {
                Ok(value as u8)
            } else {
                Err(E::custom(format!("ICMP type out of range: {}", value)))
            }
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if (0..=255).contains(&value) {
                Ok(value as u8)
            } else {
                Err(E::custom(format!("ICMP type out of range: {}", value)))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match value {
                "echo-reply" => Ok(IcmpTypes::EchoReply.0),
                "destination-unreachable" => Ok(IcmpTypes::DestinationUnreachable.0),
                "source-quench" => Ok(IcmpTypes::SourceQuench.0),
                "redirect" => Ok(IcmpTypes::RedirectMessage.0),
                "echo-request" => Ok(IcmpTypes::EchoRequest.0),
                "router-advertisement" => Ok(IcmpTypes::RouterAdvertisement.0),
                "router-solicitation" => Ok(IcmpTypes::RouterSolicitation.0),
                "time-exceeded" => Ok(IcmpTypes::TimeExceeded.0),
                "parameter-problem" => Ok(IcmpTypes::ParameterProblem.0),
                "timestamp-request" => Ok(IcmpTypes::Timestamp.0),
                "timestamp-reply" => Ok(IcmpTypes::TimestampReply.0),
                "info-request" => Ok(IcmpTypes::InformationRequest.0),
                "info-reply" => Ok(IcmpTypes::InformationReply.0),
                "address-mask-request" => Ok(IcmpTypes::AddressMaskRequest.0),
                "address-mask-reply" => Ok(IcmpTypes::AddressMaskReply.0),
                "packet-too-big" => Ok(Icmpv6Types::PacketTooBig.0),
                "nd-router-solicit" => Ok(Icmpv6Types::RouterSolicit.0),
                "nd-router-advert" => Ok(Icmpv6Types::RouterAdvert.0),
                "nd-neighbor-solicit" => Ok(Icmpv6Types::NeighborSolicit.0),
                "nd-neighbor-advert" => Ok(Icmpv6Types::NeighborAdvert.0),
                _ => Err(E::custom(format!(
                    "unknown ICMP type '{}' (use nftables type names like 'echo-request' or numeric value)",
                    value
                ))),
            }
        }
    }

    deserializer.deserialize_any(IcmpTypeVisitor)
}
