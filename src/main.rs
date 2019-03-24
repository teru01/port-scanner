extern crate rayon;

use std::{ net, env, thread, time, fs, collections };
use pnet::packet::{ tcp, ipv4, ip, ethernet, MutablePacket, Packet};
use pnet::datalink;
use pnet::transport;

const TCP_SIZE: usize = 20;
const IP_SIZE: usize = 20 + TCP_SIZE;
const ETHERNET_SIZE: usize = 14 + IP_SIZE;
const MAXIMUM_PORT_NUM: u16 = 1023;

struct PacketInfo {
    my_macaddr: String,
    default_gateway: String,
    my_ipaddr: net::Ipv4Addr,
    target_ipaddr: net::Ipv4Addr,
    my_port: u16,
    iface: String,
    scan_type: ScanType,
}

#[derive(Copy, Clone)]
enum ScanType {
    SynScan = tcp::TcpFlags::SYN as isize,
    FinScan = tcp::TcpFlags::FIN as isize,
    XmasScan = tcp::TcpFlags::FIN as isize | tcp::TcpFlags::URG as isize | tcp::TcpFlags::PSH as isize,
    NullScan = 0
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Bad nunber of arguemnts");
        std::process::exit(1);
    }

    let mut packet_info: PacketInfo = {
        let contents = fs::read_to_string(".env").expect("Failed to read env file");
        let lines: Vec<_> = contents.split('\n').collect();
        let mut map = collections::HashMap::new();
        for line in lines {
            let elm: Vec<_> = line.split('=').map(|s| s.trim()).collect();
            if elm.len() == 2 {
                map.insert(elm[0], elm[1]);
            }
        }
        PacketInfo {
            my_macaddr:      map.get("MY_MACADDR")     .expect("missing my_macaddr")     .to_string(),
            default_gateway: map.get("DEFAULT_GATEWAY").expect("missing default gateway").to_string(),
            my_ipaddr:       map.get("MY_IPADDR")      .expect("missing my_ipaddr")      .parse().expect("invalid ipaddr"),
            target_ipaddr:   "0.0.0.0".parse().expect("invalid ipaddr"),
            my_port:         map.get("MY_PORT")        .expect("missing my_port")        .parse().expect("invalid port number"),
            iface:           map.get("IFACE")          .expect("missing interface name") .to_string(),
            scan_type:       ScanType::SynScan
        }
    };

    packet_info.target_ipaddr = args[1].parse().expect("invalid target ipaddr");
    packet_info.scan_type = match args[2].as_str() {
        "sS" => ScanType::SynScan,
        "sF" => ScanType::FinScan,
        "sX" => ScanType::XmasScan,
        "sN" => ScanType::NullScan,
        _    => panic!("Undefined scan method")
    };

    // let interfaces = datalink::interfaces();
    // let interface = interfaces
    //     .into_iter()
    //     .filter(|iface| iface.name == packet_info.iface)
    //     .next()
    //     .expect("Failed to get interface");

    // let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
    //     Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
    //     Ok(_) => panic!("Unhandled channel type"),
    //     Err(e) => {
    //         panic!("Failed to create datalink channel {}", e)
    //     }
    // };

    let (mut ts, mut tr) = transport::transport_channel(20, transport::TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Tcp)).unwrap();

    rayon::join(|| send_packet(&mut ts, &packet_info),
                || receive_packets(&mut tr, &packet_info)
    );
}

// 指定のレンジにパケットを送信
fn send_packet(ts: &mut transport::TransportSender, packet_info: &PacketInfo) {
    let mut packet = build_packet(packet_info);
    for i in 1..MAXIMUM_PORT_NUM+1 {
        let mut packet = packet.clone();
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut packet[ETHERNET_SIZE-TCP_SIZE..]).unwrap();
        reregister_destination_port(i, &mut tcp_header, packet_info);
        thread::sleep(time::Duration::from_millis(5));
        ts.send_to(tcp_header, "192.168.11.1".parse().unwrap()).expect("failed to send");
    }
}

// TCPヘッダの宛先ポート情報を書き換える
fn reregister_destination_port(target: u16, tcp_header: &mut tcp::MutableTcpPacket, packet_info: &PacketInfo) {
    tcp_header.set_destination(target);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &packet_info.my_ipaddr, &packet_info.target_ipaddr);
    tcp_header.set_checksum(checksum);
}

// パケットを受信してスキャン結果を出力する。
fn receive_packets(tr: &mut transport::TransportReceiver, packet_info: &PacketInfo) {
    let mut reply_ports = Vec::new();
    loop {
        if let Some(tcp_packet) = tcp::TcpPacket::new(&tr.buffer) {
            if tcp_packet.get_destination() == packet_info.my_port {
                let target_port = tcp_packet.get_source();
                match packet_info.scan_type {
                    ScanType::SynScan => {
                        if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                            println!("port {} is open", target_port);
                        }
                    },
                    ScanType::FinScan | ScanType::XmasScan | ScanType::NullScan => {
                        reply_ports.push(target_port);
                    },
                }
                if target_port == MAXIMUM_PORT_NUM {
                    match packet_info.scan_type {
                        ScanType::FinScan | ScanType::XmasScan | ScanType::NullScan => {
                            for i in 1..MAXIMUM_PORT_NUM+1 {
                                match reply_ports.iter().find(|&&x| x == i) {
                                    None => {
                                        println!("port {} is open", i);
                                    },
                                    _ => {}
                                }
                            }
                        },
                        _ => {}
                    }
                    return;
                }
            }
        }
        tr.buffer = Vec::new();
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
    ip_header.set_total_length(IP_SIZE as u16);
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
    ethernet_header.set_destination(packet_info.default_gateway.parse().expect("invalid default gateway"));
    ethernet_header.set_source(packet_info.my_macaddr.parse().expect("invalid my_macaddr"));
    ethernet_header.set_ethertype(ethernet::EtherTypes::Ipv4);
    ethernet_header.set_payload(ip_header.packet_mut());

    return ethernet_buffer;
}
