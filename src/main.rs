use clap::Parser;
use ctrlc;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareType, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::vlan::{MutableVlanPacket, VlanPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use rand::random;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::usize;

// --- Command Line Arguments ---
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to listen on (e.g., eth0, enp0s3)
    interface: String,

    /// Send a null-byte in response to a TCP PSH (not just ACK)
    #[arg(short = 'p', long)]
    tcp_psh: bool,

    /// Skip responding to ARP requests
    #[arg(short = 'A', long)]
    no_arp: bool,

    /// Skip responding to ICMP (echo request)
    #[arg(short = 'I', long)]
    no_icmp: bool,

    /// Skip responding to TCP
    #[arg(short = 'T', long)]
    no_tcp: bool,

    /// Skip responding to UDP
    #[arg(short = 'U', long)]
    no_udp: bool,

    /// Introduce iptables rule to drop RST packets
    #[arg(short = 'r', long)]
    drop_rst: bool,

    /// Introduce iptables rule to drop ICMP port unreachable packets
    #[arg(short = 'u', long)]
    drop_port_unreachable: bool,
}

// --- Layer 2 (L2) Builders ---

fn build_ethernet_header<'a>(
    buffer: &'a mut [u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
    ethertype: EtherType,
) -> MutableEthernetPacket<'a> {
    let mut eth_packet = MutableEthernetPacket::new(buffer).unwrap();
    eth_packet.set_destination(dst_mac);
    eth_packet.set_source(src_mac);
    eth_packet.set_ethertype(ethertype);
    eth_packet
}

fn build_arp_reply<'a>(
    arp_buffer: &'a mut [u8],
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> MutableArpPacket<'a> {
    let mut arp_reply = MutableArpPacket::new(arp_buffer).unwrap();
    arp_reply.set_hardware_type(ArpHardwareType::new(1)); // Ethernet
    arp_reply.set_protocol_type(EtherTypes::Ipv4);
    arp_reply.set_hw_addr_len(6);
    arp_reply.set_proto_addr_len(4);
    arp_reply.set_operation(ArpOperations::Reply);
    arp_reply.set_sender_hw_addr(sender_mac);
    arp_reply.set_sender_proto_addr(sender_ip);
    arp_reply.set_target_hw_addr(target_mac);
    arp_reply.set_target_proto_addr(target_ip);
    arp_reply
}

// --- Layer 3 (L3) Builders ---

fn build_ipv4_header<'a>(
    buffer: &'a mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    next_protocol: IpNextHeaderProtocol,
    payload_len: usize,
) -> MutableIpv4Packet<'a> {
    let mut ipv4_packet = MutableIpv4Packet::new(buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((20 + payload_len) as u16);
    ipv4_packet.set_identification(random::<u16>()); // Use a random ID
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    ipv4_packet.set_next_level_protocol(next_protocol);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_checksum(0); // Placeholder
    ipv4_packet
}

// --- Layer 4 (L4) Builders ---

fn build_tcp_header<'a>(
    buffer: &'a mut [u8],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    src_ip: Ipv4Addr, // Needed for checksum
    dst_ip: Ipv4Addr, // Needed for checksum
) -> MutableTcpPacket<'a> {
    let mut tcp_packet = MutableTcpPacket::new(buffer).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(seq);
    tcp_packet.set_acknowledgement(ack);
    tcp_packet.set_data_offset(5); // 5 * 32-bits = 20 bytes (standard header)
    tcp_packet.set_flags(flags);
    tcp_packet.set_window(window);
    tcp_packet.set_checksum(0); // Placeholder
    tcp_packet.set_urgent_ptr(0);

    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
    tcp_packet.set_checksum(checksum);

    tcp_packet
}

fn build_udp_header<'a>(
    buffer: &'a mut [u8],
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    src_ip: Ipv4Addr, // Needed for checksum
    dst_ip: Ipv4Addr, // Needed for checksum
) -> MutableUdpPacket<'a> {
    let udp_len = 8 + payload_len; // 8 byte header + payload
    let mut udp_packet = MutableUdpPacket::new(buffer).unwrap();
    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    udp_packet.set_length(udp_len as u16);

    let checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
    udp_packet.set_checksum(checksum);

    udp_packet
}

fn build_icmp_echo_reply<'a>(
    buffer: &'a mut [u8],
    icmp_packet: &IcmpPacket,
) -> MutableEchoReplyPacket<'a> {
    let mut icmp_reply = echo_reply::MutableEchoReplyPacket::new(buffer).unwrap();

    if let Some(echo_request) = echo_request::EchoRequestPacket::new(icmp_packet.packet()) {
        icmp_reply.set_identifier(echo_request.get_identifier());
        icmp_reply.set_sequence_number(echo_request.get_sequence_number());
        icmp_reply.set_payload(echo_request.payload());
    } else {
        icmp_reply.set_payload(&icmp_packet.payload()[4..]);
    }

    let checksum = pnet::util::checksum(icmp_reply.packet(), 0);
    icmp_reply.set_checksum(checksum);

    icmp_reply
}

// --- Packet Constructors (Return Vec<u8>) ---

struct ReplyContext {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    vlan_ids: Vec<u16>, // Support multiple VLAN tags
}

/// Helper to wrap a payload in Ethernet + Optional VLANs
fn wrap_in_l2(ctx: &ReplyContext, payload: &[u8], payload_ethertype: EtherType) -> Vec<u8> {
    // Calculate total size: Ethernet(14) + VLANs(4 * N) + Payload
    let ethernet_len = 14;
    let vlan_len = ctx.vlan_ids.len() * 4;
    let total_len = ethernet_len + vlan_len + payload.len();

    let mut buffer = vec![0u8; total_len];

    // 1. Build Ethernet Header
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    eth_packet.set_destination(ctx.dst_mac);
    eth_packet.set_source(ctx.src_mac);

    if !ctx.vlan_ids.is_empty() {
        eth_packet.set_ethertype(EtherTypes::Vlan);
    } else {
        eth_packet.set_ethertype(payload_ethertype);
    }

    // 2. Build VLAN Headers
    let mut current_offset = ethernet_len;
    for (i, &vlan_id) in ctx.vlan_ids.iter().enumerate() {
        let mut vlan_packet = MutableVlanPacket::new(&mut buffer[current_offset..]).unwrap();
        vlan_packet.set_vlan_identifier(vlan_id);
        // Priority and Drop Eligible Indicator default to 0 via new()

        // Determine next protocol
        if i == ctx.vlan_ids.len() - 1 {
            // Last VLAN tag points to the actual payload
            vlan_packet.set_ethertype(payload_ethertype);
        } else {
            // Current VLAN tag points to the next VLAN tag
            vlan_packet.set_ethertype(EtherTypes::Vlan);
        }
        current_offset += 4;
    }

    // 3. Copy Payload
    buffer[current_offset..].copy_from_slice(payload);

    buffer
}

fn construct_arp_reply(
    ctx: &ReplyContext,
) -> Vec<u8> {
    const ARP_LEN: usize = 28;
    let mut arp_buffer = vec![0u8; ARP_LEN];

    // 1. Build inner ARP packet
    build_arp_reply(
        &mut arp_buffer,
        ctx.src_mac,
        ctx.src_ip,
        ctx.dst_mac,
        ctx.dst_ip,
    );

    println!("  -> ARP reply: {} is at {}", ctx.src_ip, ctx.src_mac);

    // 2. Wrap in L2 (Ethernet + VLANs)
    wrap_in_l2(ctx, &arp_buffer, EtherTypes::Arp)
}

fn construct_syn_ack(ctx: &ReplyContext, tcp_packet: &TcpPacket) -> Vec<u8> {
    const TCP_LEN: usize = 20; // No payload
    const IPV4_LEN: usize = 20 + TCP_LEN;

    let mut ipv4_buffer = vec![0u8; IPV4_LEN];
    let mut tcp_buffer = vec![0u8; TCP_LEN];

    // 1. Build L4 (TCP)
    let src_port = tcp_packet.get_destination();
    let dst_port = tcp_packet.get_source();
    let synack_ack_num = tcp_packet.get_sequence().wrapping_add(1);
    let synack_seq_num = random::<u32>();

    let mut tcp_reply = build_tcp_header(
        &mut tcp_buffer,
        src_port,
        dst_port,
        synack_seq_num,
        synack_ack_num,
        TcpFlags::SYN | TcpFlags::ACK,
        tcp_packet.get_window(),
        ctx.src_ip,
        ctx.dst_ip,
    );
    tcp_reply.set_payload(&[]);

    // 2. Build L3 (IPv4)
    let mut ipv4_reply = build_ipv4_header(
        &mut ipv4_buffer,
        ctx.src_ip,
        ctx.dst_ip,
        IpNextHeaderProtocols::Tcp,
        TCP_LEN,
    );
    ipv4_reply.set_payload(tcp_reply.packet());
    ipv4_reply.set_checksum(pnet::packet::ipv4::checksum(&ipv4_reply.to_immutable()));

    println!(
        "  -> TCP SYN+ACK reply: {}:{} -> {}:{} Seq: {}, Ack: {}",
        ctx.src_ip, src_port, ctx.dst_ip, dst_port, synack_seq_num, synack_ack_num
    );

    // 3. Wrap in L2
    wrap_in_l2(ctx, ipv4_reply.packet(), EtherTypes::Ipv4)
}

fn construct_ack(ctx: &ReplyContext, tcp_packet: &TcpPacket) -> Vec<u8> {
    const TCP_PAYLOAD: &[u8] = &[];
    const TCP_LEN: usize = 20 + 0;
    const IPV4_LEN: usize = 20 + TCP_LEN;

    let mut ipv4_buffer = vec![0u8; IPV4_LEN];
    let mut tcp_buffer = vec![0u8; TCP_LEN];

    // 1. Build L4 (TCP)
    let src_port = tcp_packet.get_destination();
    let dst_port = tcp_packet.get_source();
    let seq_num = tcp_packet.get_acknowledgement();
    let ack_num = tcp_packet
        .get_sequence()
        .wrapping_add(tcp_packet.payload().len() as u32);

    let mut tcp_reply = build_tcp_header(
        &mut tcp_buffer,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        TcpFlags::ACK,
        tcp_packet.get_window(),
        ctx.src_ip,
        ctx.dst_ip,
    );
    tcp_reply.set_payload(TCP_PAYLOAD);

    // 2. Build L3 (IPv4)
    let mut ipv4_reply = build_ipv4_header(
        &mut ipv4_buffer,
        ctx.src_ip,
        ctx.dst_ip,
        IpNextHeaderProtocols::Tcp,
        TCP_LEN,
    );
    ipv4_reply.set_payload(tcp_reply.packet());
    ipv4_reply.set_checksum(pnet::packet::ipv4::checksum(&ipv4_reply.to_immutable()));

    println!(
        "  -> TCP ACK reply: {}:{} -> {}:{} Seq: {}, Ack: {}",
        ctx.src_ip, src_port, ctx.dst_ip, dst_port, seq_num, ack_num
    );

    // 3. Wrap in L2
    wrap_in_l2(ctx, ipv4_reply.packet(), EtherTypes::Ipv4)
}

fn construct_psh_ack(ctx: &ReplyContext, tcp_packet: &TcpPacket) -> Vec<u8> {
    const TCP_PAYLOAD: &[u8] = &[0];
    let tcp_len: usize = 20 + TCP_PAYLOAD.len();
    let ipv4_len: usize = 20 + tcp_len;

    let mut ipv4_buffer = vec![0u8; ipv4_len];
    let mut tcp_buffer = vec![0u8; tcp_len];

    // 1. Build L4 (TCP)
    let src_port = tcp_packet.get_destination();
    let dst_port = tcp_packet.get_source();
    let seq_num = tcp_packet.get_acknowledgement();
    let ack_num = tcp_packet
        .get_sequence()
        .wrapping_add(tcp_packet.payload().len() as u32);

    let mut tcp_reply = build_tcp_header(
        &mut tcp_buffer,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp_packet.get_window(),
        ctx.src_ip,
        ctx.dst_ip,
    );
    tcp_reply.set_payload(TCP_PAYLOAD);

    // 2. Build L3 (IPv4)
    let mut ipv4_reply = build_ipv4_header(
        &mut ipv4_buffer,
        ctx.src_ip,
        ctx.dst_ip,
        IpNextHeaderProtocols::Tcp,
        tcp_len,
    );
    ipv4_reply.set_payload(tcp_reply.packet());
    ipv4_reply.set_checksum(pnet::packet::ipv4::checksum(&ipv4_reply.to_immutable()));

    println!(
        "  -> TCP PSH+ACK reply: {}:{} -> {}:{} Seq: {}, Ack: {}",
        ctx.src_ip, src_port, ctx.dst_ip, dst_port, seq_num, ack_num
    );

    // 3. Wrap in L2
    wrap_in_l2(ctx, ipv4_reply.packet(), EtherTypes::Ipv4)
}

fn construct_fin_ack(ctx: &ReplyContext, tcp_packet: &TcpPacket) -> Vec<u8> {
    const TCP_PAYLOAD: &[u8] = &[];
    const TCP_LEN: usize = 20 + 0;
    const IPV4_LEN: usize = 20 + TCP_LEN;

    let mut ipv4_buffer = vec![0u8; IPV4_LEN];
    let mut tcp_buffer = vec![0u8; TCP_LEN];

    // 1. Build L4 (TCP)
    let src_port = tcp_packet.get_destination();
    let dst_port = tcp_packet.get_source();
    let seq_num = tcp_packet.get_acknowledgement();
    let ack_num = tcp_packet.get_sequence().wrapping_add(1);

    let mut tcp_reply = build_tcp_header(
        &mut tcp_buffer,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        TcpFlags::FIN | TcpFlags::ACK,
        tcp_packet.get_window(),
        ctx.src_ip,
        ctx.dst_ip,
    );
    tcp_reply.set_payload(TCP_PAYLOAD);

    // 2. Build L3 (IPv4)
    let mut ipv4_reply = build_ipv4_header(
        &mut ipv4_buffer,
        ctx.src_ip,
        ctx.dst_ip,
        IpNextHeaderProtocols::Tcp,
        TCP_LEN,
    );
    ipv4_reply.set_payload(tcp_reply.packet());
    ipv4_reply.set_checksum(pnet::packet::ipv4::checksum(&ipv4_reply.to_immutable()));

    println!(
        "  -> TCP FIN+ACK reply: {}:{} -> {}:{} Seq: {}, Ack: {}",
        ctx.src_ip, src_port, ctx.dst_ip, dst_port, seq_num, ack_num
    );

    // 3. Wrap in L2
    wrap_in_l2(ctx, ipv4_reply.packet(), EtherTypes::Ipv4)
}

fn construct_udp_reply(ctx: &ReplyContext, udp_packet: &UdpPacket) -> Vec<u8> {
    const UDP_PAYLOAD: &[u8] = &[0];
    let udp_len: usize = 8 + UDP_PAYLOAD.len();
    let ipv4_len: usize = 20 + udp_len;

    let mut ipv4_buffer = vec![0u8; ipv4_len];
    let mut udp_buffer = vec![0u8; udp_len];

    // 1. Build L4 (UDP)
    let src_port = udp_packet.get_destination();
    let dst_port = udp_packet.get_source();

    let mut udp_reply = build_udp_header(
        &mut udp_buffer,
        src_port,
        dst_port,
        UDP_PAYLOAD.len(),
        ctx.src_ip,
        ctx.dst_ip,
    );
    udp_reply.set_payload(UDP_PAYLOAD);

    // 2. Build L3 (IPv4)
    let mut ipv4_reply = build_ipv4_header(
        &mut ipv4_buffer,
        ctx.src_ip,
        ctx.dst_ip,
        IpNextHeaderProtocols::Udp,
        udp_len,
    );
    ipv4_reply.set_payload(udp_reply.packet());
    ipv4_reply.set_checksum(pnet::packet::ipv4::checksum(&ipv4_reply.to_immutable()));

    println!(
        "  -> UDP reply: {}:{} -> {}:{}",
        ctx.src_ip, src_port, ctx.dst_ip, dst_port
    );

    // 3. Wrap in L2
    wrap_in_l2(ctx, ipv4_reply.packet(), EtherTypes::Ipv4)
}

fn construct_icmp_echo_reply(ctx: &ReplyContext, icmp_packet: &IcmpPacket) -> Vec<u8> {
    let icmp_payload_len = icmp_packet.payload().len();
    let icmp_len = icmp_payload_len + 4;
    let ipv4_len = 20 + icmp_len;

    let mut ipv4_buffer = vec![0u8; ipv4_len];
    let mut icmp_buffer = vec![0u8; icmp_len];

    // 1. Build L4 (ICMP)
    let icmp_reply_packet = build_icmp_echo_reply(&mut icmp_buffer, icmp_packet);
    let icmp_payload = icmp_reply_packet.packet();

    // 2. Build L3 (IPv4)
    let mut ipv4_reply = build_ipv4_header(
        &mut ipv4_buffer,
        ctx.src_ip,
        ctx.dst_ip,
        IpNextHeaderProtocols::Icmp,
        icmp_len,
    );
    ipv4_reply.set_payload(icmp_payload);
    ipv4_reply.set_checksum(pnet::packet::ipv4::checksum(&ipv4_reply.to_immutable()));

    println!("  -> ICMP Echo reply: {} -> {}", ctx.src_ip, ctx.dst_ip);

    // 3. Wrap in L2
    wrap_in_l2(ctx, ipv4_reply.packet(), EtherTypes::Ipv4)
}

// --- Iptables Management ---

fn modify_iptables_rule(
    interface_name: &str,
    rule_fragment: &str,
    remove: bool,
) -> Result<(), String> {
    let action = if remove { "-D" } else { "-I" };
    let rule_spec = format!(
        "{} OUTPUT -o {} {}",
        action, interface_name, rule_fragment
    );

    println!(
        "iptables rule: {}...",
        if remove { "Removing" } else { "Adding" }
    );

    let output = Command::new("sudo")
        .arg("iptables")
        .args(rule_spec.split_whitespace())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute iptables: {}", e))?;

    if output.status.success() {
        println!("  ✅ Rule successfully {}.", if remove { "removed" } else { "added" });
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("  ❌ Failed to execute rule. stderr: {}", stderr);
        Err(format!("Iptables command failed: {}", stderr))
    }
}

// --- Packet Handlers (Return Option<Vec<u8>>) ---

fn handle_arp_packet(
    args: &Args,
    interface: &NetworkInterface,
    ethernet_packet: &EthernetPacket,
    payload: &[u8],
    vlan_ids: Vec<u16>,
) -> Option<Vec<u8>> {
    if args.no_arp {
        return None;
    }
    if let Some(arp_packet) = ArpPacket::new(payload) {
        if arp_packet.get_operation() == ArpOperations::Request {
            println!(
                "* Received ARP Who-Has request from {} for {}",
                arp_packet.get_sender_proto_addr(),
                arp_packet.get_target_proto_addr()
            );

            let ctx = ReplyContext {
                src_ip: arp_packet.get_target_proto_addr(),
                dst_ip: arp_packet.get_sender_proto_addr(),
                src_mac: interface.mac.unwrap_or(MacAddr::zero()),
                dst_mac: ethernet_packet.get_source(),
                vlan_ids,
            };

            return Some(construct_arp_reply(&ctx));
        }
    }
    None
}

fn handle_tcp_packet(
    args: &Args,
    ctx: &ReplyContext,
    tcp_packet: &TcpPacket,
) -> Option<Vec<u8>> {
    if tcp_packet.get_flags() == TcpFlags::SYN {
        println!(
            "* Received TCP SYN: {}:{} -> {}:{}",
            ctx.dst_ip,
            tcp_packet.get_source(),
            ctx.src_ip,
            tcp_packet.get_destination()
        );
        Some(construct_syn_ack(ctx, tcp_packet))
    } else if (tcp_packet.get_flags() & TcpFlags::PSH) != 0 {
        println!(
            "* Received TCP PSH: {}:{} -> {}:{}",
            ctx.dst_ip,
            tcp_packet.get_source(),
            ctx.src_ip,
            tcp_packet.get_destination()
        );
        if args.tcp_psh {
            Some(construct_psh_ack(ctx, tcp_packet))
        } else {
            Some(construct_ack(ctx, tcp_packet))
        }
    } else if (tcp_packet.get_flags() & TcpFlags::FIN) != 0 {
        println!(
            "* Received TCP FIN: {}:{} -> {}:{}",
            ctx.dst_ip,
            tcp_packet.get_source(),
            ctx.src_ip,
            tcp_packet.get_destination()
        );
        Some(construct_fin_ack(ctx, tcp_packet))
    } else {
        None
    }
}

fn handle_ipv4_packet(
    args: &Args,
    interface: &NetworkInterface,
    ethernet_packet: &EthernetPacket,
    payload: &[u8],
    vlan_ids: Vec<u16>,
) -> Option<Vec<u8>> {
    // Use the provided payload (which might be extracted from VLAN)
    if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
        let ctx = ReplyContext {
            src_ip: ipv4_packet.get_destination(),
            dst_ip: ipv4_packet.get_source(),
            src_mac: interface.mac.unwrap_or(ethernet_packet.get_destination()),
            dst_mac: ethernet_packet.get_source(),
            vlan_ids,
        };

        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp if !args.no_tcp => {
                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                    return handle_tcp_packet(args, &ctx, &tcp_packet);
                }
            }
            IpNextHeaderProtocols::Udp if !args.no_udp => {
                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                    println!(
                        "* Received UDP Packet: {}:{} -> {}:{}",
                        ctx.dst_ip,
                        udp_packet.get_source(),
                        ctx.src_ip,
                        udp_packet.get_destination()
                    );
                    return Some(construct_udp_reply(&ctx, &udp_packet));
                }
            }
            IpNextHeaderProtocols::Icmp if !args.no_icmp => {
                if let Some(icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                    if icmp_packet.get_icmp_type() == IcmpTypes::EchoRequest {
                        println!(
                            "* Received ICMP Echo Request (Ping): {} -> {}",
                            ctx.dst_ip, ctx.src_ip
                        );
                        return Some(construct_icmp_echo_reply(&ctx, &icmp_packet));
                    }
                }
            }
            _ => { /* Ignore other protocols */ }
        }
    }
    None
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let interface_name = &args.interface;

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

    let ip_addr = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4() && !ip.ip().is_loopback())
        .map(|ip| ip.ip().to_string())
        .unwrap_or_else(|| "N/A".to_string());

    println!(
        "🚀 Starting raw socket listener on interface: **{}** (IP: {})",
        interface.name, ip_addr
    );
    println!(
        "   MAC Address: {}",
        interface
            .mac
            .map(|m| m.to_string())
            .unwrap_or_else(|| "N/A".to_string())
    );

    let drop_rst_rule_active = Arc::new(AtomicBool::new(false));
    const TCP_RST_RULE: &str = "-p tcp --tcp-flags RST RST -j DROP";
    if args.drop_rst {
        if modify_iptables_rule(interface_name, TCP_RST_RULE, false).is_ok() {
            drop_rst_rule_active.store(true, Ordering::SeqCst);
        }
    }

    let drop_unreachable_rule_active = Arc::new(AtomicBool::new(false));
    const ICMP_UNREACHABLE_RULE: &str = "-p icmp --icmp-type port-unreachable -j DROP";
    if args.drop_port_unreachable {
        if modify_iptables_rule(interface_name, ICMP_UNREACHABLE_RULE, false).is_ok() {
            drop_unreachable_rule_active.store(true, Ordering::SeqCst);
        }
    }

    let cleanup_rst_rule_active = drop_rst_rule_active.clone();
    let cleanup_unreachable_rule_active = drop_unreachable_rule_active.clone();
    let cleanup_interface_name = interface_name.clone();
    ctrlc::set_handler(move || {
        println!("\n🛑 Ctrl+C detected. Shutting down and cleaning up iptables...");
        if cleanup_rst_rule_active.load(Ordering::SeqCst) {
            let _ = modify_iptables_rule(&cleanup_interface_name, TCP_RST_RULE, true);
        }
        if cleanup_unreachable_rule_active.load(Ordering::SeqCst) {
            let _ = modify_iptables_rule(&cleanup_interface_name, ICMP_UNREACHABLE_RULE, true);
        }
        std::process::exit(0);
    })
    .map_err(|e| format!("Error setting Ctrl+C handler: {}", e))?;

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unsupported channel type".to_string()),
        Err(e) => return Err(format!("Failed to create datalink channel: {}", e)),
    };

    println!("👂 Listening for packets...");
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    let mut payload = ethernet_packet.payload();
                    let mut ethertype = ethernet_packet.get_ethertype();
                    let mut vlan_ids = Vec::new();

                    // Check for VLAN tags
                    while ethertype == EtherTypes::Vlan {
                        if let Some(vlan_packet) = VlanPacket::new(payload) {
                            vlan_ids.push(vlan_packet.get_vlan_identifier());
                            ethertype = vlan_packet.get_ethertype();
                            payload = &payload[4..]; // Unwrap VLAN to get inner payload
                        } else {
                            break;
                        }
                    }

                    let response_packet = match ethertype {
                        EtherTypes::Arp => {
                            handle_arp_packet(&args, &interface, &ethernet_packet, payload, vlan_ids)
                        }
                        EtherTypes::Ipv4 => {
                            handle_ipv4_packet(&args, &interface, &ethernet_packet, payload, vlan_ids)
                        }
                        _ => None,
                    };

                    // If a response was generated, send it
                    if let Some(data) = response_packet {
                        if let Err(e) = tx.send_to(&data, None).unwrap_or_else(|| Err(Error::new(ErrorKind::WouldBlock, "Buffer full"))) {
                            eprintln!("Failed to send packet: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
