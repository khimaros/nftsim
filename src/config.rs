// src/config.rs

use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SimConfig {
    pub network: Network,
    #[serde(default)]
    pub guest_setup: GuestSetup,
    #[serde(rename = "tests")]
    pub test_cases: Vec<TestCase>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    pub ip: String,
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
    /// The nftables verdict (accept, drop, reject)
    #[serde(deserialize_with = "deserialize_lowercase_verdict")]
    pub verdict: Verdict,

    /// Which nftables hook processes this packet (prerouting, input, forward, output, postrouting)
    /// If not specified, we infer: if to_interface is set -> forward hook, else -> input hook
    #[serde(default)]
    pub hook: Option<String>,

    /// For forwarded packets: which interface the packet exits on
    /// Setting this implies hook = "forward"
    #[serde(default)]
    pub to_interface: Option<String>,

    /// Expected source NAT address (checked at postrouting)
    #[serde(default)]
    pub src_nat: Option<String>,

    /// Expected destination NAT address (checked at prerouting)
    #[serde(default)]
    pub dst_nat: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
}

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
            // Try service name lookup using getservbyname
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
