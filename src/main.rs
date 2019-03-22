// use pnet::packet::tcp::TcpPacket;
use pnet::packet::{ tcp, ipv4, ip, ethernet, MutablePacket, Packet};
use pnet::packet::tcp::TcpOption;
use pnet::datalink;
use pnet::datalink::Channel;
use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;
use std::{ env, thread, io, time };

extern crate rand;
extern crate serde;
extern crate rayon;
use rayon::prelude::*;

const TCP_SIZE: usize = 20;
const IP_SIZE: usize = 20 + TCP_SIZE;
const ETHERNET_SIZE: usize = 14 + IP_SIZE;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Bad nunber of arguemnts");
        std::process::exit(1);
    }

    let myaddr: Ipv4Addr = "192.168.11.22".parse().unwrap();
    let addr: Ipv4Addr = args[1].parse().unwrap();
    let _method = &args[2];
    let my_port = 33333;

    let interface_name = env::args().nth(3).unwrap();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == interface_name)
        .next()
        .expect("Failed to get interface");
    
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!("Failed to create datalink channel {}", e)
        }
    };
    // rayon::join(|| send_packet(&myaddr, &addr, my_port), oper_b: B)
    send_packet(&mut tx, &myaddr, &addr, my_port);
}

fn send_packet(tx: &mut Box<dyn datalink::DataLinkSender>, myaddr: &Ipv4Addr, addr: &Ipv4Addr, my_port: u16) {
    let (mut packet, mut _tcp_data) = build_my_packet(myaddr, addr, my_port);
    for i in 50..100 {
        // let mut packet = packet.clone();
        let mut tcp_packet = tcp::MutableTcpPacket::new(&mut packet[ETHERNET_SIZE-TCP_SIZE..]).unwrap();

        reregister_destination_port(i, &mut tcp_packet, myaddr, addr);
        tx.send_to(&packet, None);
    }
}

fn reregister_destination_port(n: u16, tcp_packet: &mut tcp::MutableTcpPacket, myaddr: &Ipv4Addr, addr: &Ipv4Addr) {
    tcp_packet.set_destination(n);
    let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), myaddr, addr);
    tcp_packet.set_checksum(checksum);
}

// fn receive_packets(rx: datalink::DataLinkReceiver, addr: &Ipv4Addr, myaddr: &Ipv4Addr) -> Result<(), io::Error> {
//     loop {
//         let frame = match rx.next() {
//             Ok(frame) => frame,
//             Err(_) => {
//                 continue
//             }
//         };
//         let frame = ethernet::EthernetPacket::new(frame).unwrap();
//         match frame.get_ethertype() {
//             ethernet::EtherTypes::Ipv4 => {
//                 if let Some(packet) = ipv4::Ipv4Packet::new(frame.payload()) {
//                     if !(&packet.get_source() == &addr && &packet.get_destination() == &myaddr) {
//                         continue;
//                     }
//                     let tcp = match packet.get_next_level_protocol() {
//                         ip::IpNextHeaderProtocols::Tcp => {
//                             if let Some(tcp) = tcp::TcpPacket::new(packet.payload()) {
//                                 tcp
//                             } else {
//                                 continue
//                             }
//                         }
//                         _ => continue
//                     };

//                     if tcp.get_destination() == my_port {
//                         let target_port = tcp.get_source();
//                         if tcp.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
//                             println!("port {} is open", target_port);
//                         } else if tcp.get_flags() == tcp::TcpFlags::RST | tcp::TcpFlags::ACK {
//                             println!("port {} is close", target_port);
//                         }
//                     }
//                 }
//             },
//             _ => {}
//         }
//     }
// }

fn build_my_packet(myaddr: &Ipv4Addr, addr: &Ipv4Addr, source_port: u16) -> ([u8; ETHERNET_SIZE], [u8; TCP_SIZE]){
    let mut ethernet_buffer = [0u8; ETHERNET_SIZE];
    
    let mut tcp_header = [0u8; TCP_SIZE];
    let mut tcp_packet = tcp::MutableTcpPacket::new(&mut tcp_header[..]).unwrap();
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(22222);
    // tcp_packet.set_sequence(12345);
    // tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    // tcp_packet.set_reserved(0);
    tcp_packet.set_flags(tcp::TcpFlags::SYN); //SYNパケット
    // tcp_packet.set_window(0);
    // tcp_packet.set_options(&vec![TcpOption::mss(1460)]);
    let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &myaddr, &addr);
    tcp_packet.set_checksum(checksum);
    // tcp_packet.set_urgent_ptr(0);

    let mut ip_header = [0u8; IP_SIZE];
    let mut ipv4_packet = ipv4::MutableIpv4Packet::new(&mut ip_header[..]).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    // ipv4_packet.set_dscp(0);
    // ipv4_packet.set_ecn(0);
    ipv4_packet.set_total_length(IP_SIZE as u16); //?
    // ipv4_packet.set_identification(rand::random::<u16>());
    // ipv4_packet.set_flags(0);
    // ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(255);
    ipv4_packet.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(myaddr.clone());
    ipv4_packet.set_destination(addr.clone());

    // let tcp_mut = tcp_packet.packet_mut();
    let checksum_ip = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum_ip);

    ipv4_packet.set_payload(tcp_packet.packet_mut());

    let mut ethernet_packet = ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let macAddr: datalink::MacAddr = "88:57:ee:b5:80:53".parse().unwrap();
    ethernet_packet.set_destination(macAddr);
    ethernet_packet.set_source(MacAddr::new(0xf4,0x0f,0x24,0x27,0xdb,0x00));
    ethernet_packet.set_ethertype(ethernet::EtherTypes::Ipv4);
    ethernet_packet.set_payload(ipv4_packet.packet_mut());

    return (ethernet_buffer, tcp_header);
}

fn build_random_packet(my_addr: &Ipv4Addr, destination_ip: &Ipv4Addr) -> Option<[u8; 66]> {
    const ETHERNET_HEADER_LEN: usize = 14;
    const TCP_HEADER_LEN: usize = 32;
    const IPV4_HEADER_LEN: usize = 20;

    let mut tmp_packet = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN];
    
    // Setup Ethernet Header
    {
        let mut eth_header = ethernet::MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(MacAddr::new(0x88, 0x57, 0xee, 0xb5, 0x80, 0x53));
        eth_header.set_source(MacAddr::new(0xf4,0x0f,0x24,0x27,0xdb,0x00));
        eth_header.set_ethertype(ethernet::EtherTypes::Ipv4);
    }

    // Setup IP header
    {
        let mut ip_header = ipv4::MutableIpv4Packet::new(&mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)]).unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_fragment_offset(16384);
        ip_header.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
        ip_header.set_source(my_addr.clone());
        ip_header.set_destination(destination_ip.clone());
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(128);
        ip_header.set_version(4);
        ip_header.set_flags(ipv4::Ipv4Flags::DontFragment);

        let checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // Setup TCP header
    {
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();

        tcp_header.set_source(rand::random::<u16>());
        tcp_header.set_destination(80);

        tcp_header.set_flags(tcp::TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(rand::random::<u32>());

        tcp_header.set_options(&vec![TcpOption::mss(1460)]);

        let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), my_addr, &destination_ip);
        tcp_header.set_checksum(checksum);
    }

    Some(tmp_packet)
}
