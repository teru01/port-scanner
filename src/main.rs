extern crate rand;
extern crate serde;
extern crate rayon;

use std::{ net, env, thread, time, io, fs };

use pnet::packet::{ tcp, ipv4, ip, ethernet, MutablePacket, Packet};
use pnet::datalink;
use pnet::datalink::Channel;

const TCP_SIZE: usize = 20;
const IP_SIZE: usize = 20 + TCP_SIZE;
const ETHERNET_SIZE: usize = 14 + IP_SIZE;
const MAXIMUM_PORT_NUM: u16 = 1000;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[derive(Deserialize)]
struct PacketInfo {
    my_macaddr: String,
    default_gateway: String,
    my_ipaddr: net::Ipv4Addr,
    target_ipaddr: net::Ipv4Addr,
    my_port: u16,
    scan_type: isize,
    iface: String
}

#[derive(Deserialize, Copy, Clone)]
enum ScanType {
    SYN_SCAN = tcp::TcpFlags::SYN as isize,
    FIN_SCAN = tcp::TcpFlags::FIN as isize,
    XMAS_SCAN = tcp::TcpFlags::FIN as isize | tcp::TcpFlags::URG as isize | tcp::TcpFlags::PSH as isize,
    NULL_SCAN = 0
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Bad nunber of arguemnts");
        std::process::exit(1);
    }
    let mut packet_info: PacketInfo = match fs::File::open("info.json") {
        Ok(file) => {
            let reader = io::BufReader::new(file);
            serde_json::from_reader(reader).expect("Failed to read from json")
        },
        Err(e) => {
            eprintln!("{:?}", e);
            std::process::exit(1);
        }
    };

    packet_info.target_ipaddr = args[1].parse().unwrap();

    if &args[2] == "sS" {
        packet_info.scan_type = ScanType::SYN_SCAN
    } else if &args[2] == "sF" {
        packet_info.scan_type = ScanType::FIN_SCAN
    } else if &args[2] == "sX" {
        packet_info.scan_type = ScanType::XMAS_SCAN
    } else if &args[2] == "sN" {
        packet_info.scan_type = ScanType::NULL_SCAN
    } else {
        panic!("Undefined scan method");
    }

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == packet_info.iface)
        .next()
        .expect("Failed to get interface");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!("Failed to create datalink channel {}", e)
        }
    };

    rayon::join(|| send_packet(&mut tx, &packet_info),
                || receive_packets(&mut rx, &packet_info)
    );
}

// 指定のレンジにパケットを送信
fn send_packet(tx: &mut Box<dyn datalink::DataLinkSender>, packet_info: &PacketInfo) {
    let mut packet = build_packet(packet_info);
    for i in 1..MAXIMUM_PORT_NUM {
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut packet[ETHERNET_SIZE-TCP_SIZE..]).unwrap();
        reregister_destination_port(i, &mut tcp_header, packet_info);
        thread::sleep(time::Duration::from_millis(5));
        tx.send_to(&packet, None);
    }
}

// TCPヘッダの宛先ポート情報を書き換える
fn reregister_destination_port(target: u16, tcp_header: &mut tcp::MutableTcpPacket, packet_info: &PacketInfo) {
    tcp_header.set_destination(target);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &packet_info.my_ipaddr, &packet_info.target_ipaddr);
    tcp_header.set_checksum(checksum);
}

// パケットを受信してスキャン結果を出力する。
fn receive_packets(rx: &mut Box<dyn datalink::DataLinkReceiver>, packet_info: &PacketInfo) {
    loop {
        let frame = match rx.next() {
            Ok(frame) => frame,
            Err(_) => {
                continue
            }
        };
        let frame = ethernet::EthernetPacket::new(frame).unwrap();
        match frame.get_ethertype() {
            ethernet::EtherTypes::Ipv4 => {
                if let Some(packet) = ipv4::Ipv4Packet::new(frame.payload()) {
                    // ターゲットから自ホスト宛て以外のものは無視
                    if !(packet.get_source() == packet_info.target_ipaddr && packet.get_destination() == packet_info.my_ipaddr) {
                        continue;
                    }
                    let tcp = match packet.get_next_level_protocol() {
                        ip::IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = tcp::TcpPacket::new(packet.payload()) {
                                tcp
                            } else {
                                continue
                            }
                        }
                        _ => continue
                    };

                    if tcp.get_destination() == packet_info.my_port {
                        let target_port = tcp.get_source();
                        match packet_info.scan_type {
                            ScanType::SYN_SCAN => {

                            },
                            ScanType::FIN_SCAN => {

                            },
                            ScanType::XMAS_SCAN => {

                            },
                            ScanType::NULL_SCAN => {

                            }
                        }
                        if tcp.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                            println!("port {} is open", target_port);
                        } else if tcp.get_flags() == tcp::TcpFlags::RST | tcp::TcpFlags::ACK {
                            // println!("port {} is close", target_port);
                        }
                        if target_port == MAXIMUM_PORT_NUM - 1 {
                            return;
                        }
                    }
                }
            },
            _ => { continue; }
        }
    }
}

// パケットを生成する。
fn build_packet(packet_info: &PacketInfo) -> [u8; ETHERNET_SIZE]{
    // TCPヘッダの作成
    let mut tcp_buffer = [0u8; TCP_SIZE];
    let mut tcp_header = tcp::MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
    tcp_header.set_source(packet_info.my_port);
    tcp_header.set_destination(22222);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(packet_info.scan_type as u16);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &packet_info.my_ipaddr, &packet_info.target_ipaddr);
    tcp_header.set_checksum(checksum);

    // IPヘッダの作成
    let mut ip_buffer = [0u8; IP_SIZE];
    let mut ip_header = ipv4::MutableIpv4Packet::new(&mut ip_buffer[..]).unwrap();
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(IP_SIZE as u16); //?
    ip_header.set_ttl(255);
    ip_header.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
    ip_header.set_source(packet_info.my_ipaddr.clone());
    ip_header.set_destination(packet_info.target_ipaddr.clone());
    let checksum_ip = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum_ip);
    ip_header.set_payload(tcp_header.packet_mut());

    // Ethernetヘッダの作成
    let mut ethernet_buffer = [0u8; ETHERNET_SIZE];
    let mut ethernet_header = ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_header.set_destination(packet_info.default_gateway.parse().unwrap());
    ethernet_header.set_source(packet_info.my_macaddr.parse().unwrap());
    ethernet_header.set_ethertype(ethernet::EtherTypes::Ipv4);
    ethernet_header.set_payload(ip_header.packet_mut());

    return ethernet_buffer;
}
