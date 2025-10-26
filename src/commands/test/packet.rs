// src/commands/test/packet.rs
//
// Packet building functions for nftsim
// Builds proper Ethernet frames with IPv4/IPv6 support using pnet_packet

use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet_packet::udp::MutableUdpPacket;
use std::net::IpAddr;

pub(super) fn get_protocol(
    transport: &crate::config::Transport,
    is_ipv6: bool,
) -> IpNextHeaderProtocol {
    match transport {
        crate::config::Transport::Tcp(_) => IpNextHeaderProtocol::new(6),
        crate::config::Transport::Udp(_) => IpNextHeaderProtocol::new(17),
        crate::config::Transport::Icmp(_) => {
            if is_ipv6 {
                IpNextHeaderProtocol::new(58) // ICMPv6
            } else {
                IpNextHeaderProtocol::new(1) // ICMP
            }
        }
    }
}

/// Build transport layer with checksums (TCP/UDP/ICMP)
pub(super) fn build_transport_layer(
    transport: &crate::config::Transport,
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
) -> Vec<u8> {
    match transport {
        crate::config::Transport::Tcp(cfg) => {
            let payload_len = cfg.payload.as_ref().map_or(0, |p| p.len());
            let mut buf = vec![0u8; 20 + payload_len];

            {
                let mut tcp = MutableTcpPacket::new(&mut buf[..20]).unwrap();
                tcp.set_source(cfg.source_port);
                tcp.set_destination(cfg.dest_port);
                tcp.set_sequence(1);
                tcp.set_acknowledgement(0);
                tcp.set_data_offset(5);
                tcp.set_reserved(0);

                let mut flags = 0u8;
                for f in &cfg.flags {
                    flags |= match f.as_str() {
                        "SYN" => TcpFlags::SYN,
                        "ACK" => TcpFlags::ACK,
                        "FIN" => TcpFlags::FIN,
                        "RST" => TcpFlags::RST,
                        "PSH" => TcpFlags::PSH,
                        "URG" => TcpFlags::URG,
                        _ => 0,
                    };
                }
                tcp.set_flags(flags);
                tcp.set_window(65535);
                tcp.set_urgent_ptr(0);
            }

            if let Some(payload) = &cfg.payload {
                buf[20..].copy_from_slice(payload);
            }

            // Calculate checksum with pseudo-header
            let csum = match (src_ip, dst_ip) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => pnet_packet::tcp::ipv4_checksum(
                    &pnet_packet::tcp::TcpPacket::new(&buf).unwrap(),
                    src,
                    dst,
                ),
                (IpAddr::V6(src), IpAddr::V6(dst)) => pnet_packet::tcp::ipv6_checksum(
                    &pnet_packet::tcp::TcpPacket::new(&buf).unwrap(),
                    src,
                    dst,
                ),
                _ => 0,
            };
            buf[16] = (csum >> 8) as u8;
            buf[17] = (csum & 0xFF) as u8;

            buf
        }
        crate::config::Transport::Udp(cfg) => {
            let payload_len = cfg.payload.as_ref().map_or(0, |p| p.len());
            let mut buf = vec![0u8; 8 + payload_len];

            {
                let mut udp = MutableUdpPacket::new(&mut buf[..8]).unwrap();
                udp.set_source(cfg.source_port);
                udp.set_destination(cfg.dest_port);
                udp.set_length((8 + payload_len) as u16);
            }

            if let Some(payload) = &cfg.payload {
                buf[8..].copy_from_slice(payload);
            }

            // Calculate checksum with pseudo-header
            let csum = match (src_ip, dst_ip) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => pnet_packet::udp::ipv4_checksum(
                    &pnet_packet::udp::UdpPacket::new(&buf).unwrap(),
                    src,
                    dst,
                ),
                (IpAddr::V6(src), IpAddr::V6(dst)) => pnet_packet::udp::ipv6_checksum(
                    &pnet_packet::udp::UdpPacket::new(&buf).unwrap(),
                    src,
                    dst,
                ),
                _ => 0,
            };
            let final_csum = if csum == 0 { 0xFFFF } else { csum };
            buf[6] = (final_csum >> 8) as u8;
            buf[7] = (final_csum & 0xFF) as u8;

            buf
        }
        crate::config::Transport::Icmp(cfg) => {
            let payload_len = cfg.payload.as_ref().map_or(0, |p| p.len());
            let mut buf = vec![0u8; 8 + payload_len];

            // For IPv6, translate ICMPv4 types to ICMPv6 types
            let is_ipv6 = matches!(src_ip, IpAddr::V6(_));
            let icmp_type_num = if is_ipv6 {
                // Translate common ICMP types to ICMPv6 equivalents
                match cfg.icmp_type {
                    0 => 129,           // Echo Reply: ICMPv4 type 0 -> ICMPv6 type 129
                    3 => 1,             // Destination Unreachable: ICMPv4 type 3 -> ICMPv6 type 1
                    8 => 128,           // Echo Request: ICMPv4 type 8 -> ICMPv6 type 128
                    11 => 3,            // Time Exceeded: ICMPv4 type 11 -> ICMPv6 type 3
                    _ => cfg.icmp_type, // Pass through other types
                }
            } else {
                cfg.icmp_type
            };

            // Directly set the type and code bytes since IcmpTypes enum doesn't cover ICMPv6
            buf[0] = icmp_type_num;
            buf[1] = cfg.code;

            // ID and sequence (bytes 4-7)
            buf[4..6].copy_from_slice(&[0x00, 0x00]);
            buf[6..8].copy_from_slice(&[0x00, 0x01]);

            if let Some(payload) = &cfg.payload {
                buf[8..].copy_from_slice(payload);
            }

            // Calculate checksum (for ICMPv6, this needs pseudo-header)
            if is_ipv6 {
                // ICMPv6 uses a pseudo-header checksum like TCP/UDP
                let csum = match (src_ip, dst_ip) {
                    (IpAddr::V6(src), IpAddr::V6(dst)) => pnet_packet::icmpv6::checksum(
                        &pnet_packet::icmpv6::Icmpv6Packet::new(&buf).unwrap(),
                        src,
                        dst,
                    ),
                    _ => 0,
                };
                buf[2] = (csum >> 8) as u8;
                buf[3] = (csum & 0xFF) as u8;
            } else {
                // ICMPv4 uses simple checksum
                let csum =
                    pnet_packet::icmp::checksum(&pnet_packet::icmp::IcmpPacket::new(&buf).unwrap());
                buf[2] = (csum >> 8) as u8;
                buf[3] = (csum & 0xFF) as u8;
            }

            buf
        }
    }
}

/// Build a proper Ethernet frame with IPv4/IPv6 support using pnet_packet
pub(super) fn build_test_frame(packet: &crate::config::Packet, socket_idx: usize) -> Vec<u8> {
    // Parse IP addresses to determine version
    let src_ip = match packet.source_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return Vec::new(),
    };
    let dst_ip = match packet.dest_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return Vec::new(),
    };

    // Build transport layer first
    let transport_data = build_transport_layer(&packet.transport, &src_ip, &dst_ip);

    // Calculate sizes
    let eth_len = 14;
    let ip_len = match (&src_ip, &dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 20,
        (IpAddr::V6(_), IpAddr::V6(_)) => 40,
        _ => return Vec::new(), // Mixed IP versions not supported
    };

    let mut frame = vec![0u8; eth_len + ip_len + transport_data.len()];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut frame[..eth_len]).unwrap();
        eth.set_destination([0x00, 0x00, 0x00, 0x00, 0x00, (socket_idx + 1) as u8].into());
        eth.set_source([0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into());
        eth.set_ethertype(match &src_ip {
            IpAddr::V4(_) => EtherTypes::Ipv4,
            IpAddr::V6(_) => EtherTypes::Ipv6,
        });
    }

    // IP header and payload
    let is_ipv6 = matches!(src_ip, IpAddr::V6(_));

    match (&src_ip, &dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut ip = MutableIpv4Packet::new(&mut frame[eth_len..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_dscp(0);
            ip.set_ecn(0);
            ip.set_total_length((ip_len + transport_data.len()) as u16);
            ip.set_identification(1);
            ip.set_flags(0);
            ip.set_fragment_offset(0);
            ip.set_ttl(64);
            ip.set_next_level_protocol(get_protocol(&packet.transport, is_ipv6));
            ip.set_source(*src);
            ip.set_destination(*dst);

            let csum = pnet_packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(csum);
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut ip = MutableIpv6Packet::new(&mut frame[eth_len..]).unwrap();
            ip.set_version(6);
            ip.set_traffic_class(0);
            ip.set_flow_label(0);
            ip.set_payload_length(transport_data.len() as u16);
            ip.set_next_header(get_protocol(&packet.transport, is_ipv6));
            ip.set_hop_limit(64);
            ip.set_source(*src);
            ip.set_destination(*dst);
            // IPv6 has no header checksum
        }
        _ => return Vec::new(),
    }

    // Copy transport data
    frame[eth_len + ip_len..].copy_from_slice(&transport_data);

    frame
}
