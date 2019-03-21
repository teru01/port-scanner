// use pnet::packet::tcp::TcpPacket;
use pnet::packet::{ tcp, ipv4, ip, ethernet, MutablePacket, Packet};
use pnet::datalink;
use pnet::datalink::Channel;
use std::net::Ipv4Addr;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Bad nunber of arguemnts");
        std::process::exit(1);
    }

    let myaddr: Ipv4Addr = "192.168.11.22".parse().unwrap();
    let addr: Ipv4Addr = args[1].parse().unwrap();
    let _method = &args[2];

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

    // thread::spawn(move || {
    //     recieve_packets(rx).unwrap();
    // });


    let mut buf: [u8; 20] = [0u8; 20];
    let mut tcp_packet = tcp::MutableTcpPacket::new(&mut buf[..]).unwrap();
    tcp_packet.set_source(33333);
    tcp_packet.set_destination(5432);
    // tcp_packet.set_sequence(0);
    // tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    // tcp_packet.set_reserved(0);
    tcp_packet.set_flags(2); //SYNパケット
    // tcp_packet.set_window(0);
    let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &myaddr, &addr);
    tcp_packet.set_checksum(checksum);
    // tcp_packet.set_urgent_ptr(0);

    let mut buf: [u8; 20] = [0u8; 20];
    let mut ipv4_packet = ipv4::MutableIpv4Packet::new(&mut buf[..]).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    // ipv4_packet.set_dscp(0);
    // ipv4_packet.set_ecn(0);
    ipv4_packet.set_total_length(100); //?
    // ipv4_packet.set_identification(0);
    // ipv4_packet.set_flags(0);
    // ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(255);
    ipv4_packet.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
    // ipv4_packet.set_checksum(0);
    ipv4_packet.set_source(myaddr);
    ipv4_packet.set_destination(addr);

    ipv4_packet.set_payload(tcp_packet.packet_mut());

    tx.send_to(ipv4_packet.packet(), None);

    // パケット作って送信する。
    // 返事をまつ。
    // 返事がきたらポートの解放状況がわかる

    // 送信したパケットに対する返答という判断をどのように行うか？ => 相手から自分のアドレス、送信元ポートに届くもの。
    // どのポートに送ったものという判断は？ => タイムアウトをつけて同期にする or 相手の返答ポート
    // メインスレッド：パケットの送信。
    // サブスレッド：パケットの受信
}

// fn recieve_packets(rx: datalink::DataLinkReceiver) {

// }
