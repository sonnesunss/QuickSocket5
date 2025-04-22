use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::net::{Ipv4Addr, TcpListener};

use s5lib::socks5lib::{self, AuthMethod};

mod s5lib;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bnd_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
    let listener = TcpListener::bind(bnd_addr)?;

    let mut buffer: [u8; 255] = [0; 255];
    let mut auth_method = AuthMethod::NoAuth;

    match listener.accept() {
        Ok((mut tcp_stream, _socket_addr)) => {
            let mut bufreader = BufReader::new(&tcp_stream);

            // 读取客户端写入的内容
            let _read_size_from_client = bufreader.read(&mut buffer)?;

            println!(
                "Debug Info: read from client -> {:?}",
                &buffer[.._read_size_from_client]
            );

            // 构造一个服务端协商响应并写到tcp_stream
            // 这里应该根据客户端的内容来做选择，有些客户端比较规矩会发来支持列表，从中选择一个即可
            // 有些则比较野性，本支持更多却只发来一个，那没得选
            // 假设无定制化需求
            if buffer[0] == socks5lib::SOCKS5_VERSION {
                // 解析来自客户端发来的支持的认证方法
                auth_method = AuthMethod::from_byte(buffer[2]).unwrap_or(AuthMethod::NoAuth);

                let ss5_negotiation_resp = socks5lib::s5server_negotiation_resp::new(auth_method);
                let r = tcp_stream.write_all(&ss5_negotiation_resp.to_bytes())?;

                println!(
                    "Server Debug Info: {:?} - result {:?}",
                    &ss5_negotiation_resp.to_bytes(),
                    r
                );
            } else {
                drop(tcp_stream);
            }
        }
        Err(e) => eprintln!("{}", e),
    }

    Ok(())
}
