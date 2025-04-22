///
/// Socks5 Server side structure
///

/*
   2. Server negotiation response

   The server selects from one of the methods given in METHODS, and
   sends a METHOD selection message:

    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |  -> bytes
    +----+--------+

    取值范围可以看下面客户端支持的方法认证列表那一部分注释

*/
pub struct s5server_negotiation_resp {
    ver: u8,
    method: u8,
}

/*
    4. RFC1929 - Server response Negotiation Verification Result for user/password authentication

    +----+--------+
    |VER | STATUS |
    +----+--------+
    | 1  |   1    |  -> bytes
    +----+--------+

    具体认证方法的值以及含义可以看下面客户端请求结构定义那边的注释
*/
pub struct s5server_user_pw_negotiation_verification_result {
    ver: u8,
    status: u8,
}

/*
   6. Server Replies

   The SOCKS request information is sent by the client as soon as it has
   established a connection to the SOCKS server, and completed the
   authentication negotiations.  The server evaluates the request, and
   returns a reply formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |  -> bytes
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address,
             o 0x01 == IPV4(4 bytes),
             o 0x03 == domain, variable length
             o 0x04 == IPV6(16 bytes)
             o domain size -> The domain name has a variable length,
                with the first byte indicating the length of the domain name (1-255 bytes),
                followed by the domain name data.

          o  BND.ADDR
          o  Bnd.PORT

    1. 这里有个地方需要注意下: ATYP出标识了地址类型，其后的BND.ADDR标识了绑定地址，其长度根据atype的类型不同而不同
          当ATYP是0x03域名时, 第一个字节标明域名长度，后面的才是真实的域名字节数据
    2. 当socks5服务器与relay服务器是一体的在同一台服务器上时，bnd.addr, bnd.port的值全部为0,
          当它们拆分开时，这两个值是relay server的地址，是需要告知给socks5客户端的
*/
pub struct s5server_reply {
    ver: u8,
    rep: u8,
    rev: u8,
    atyp: u8,
    bnd_addr: Vec<u8>, // 绑定地址类型，当是域名时，第一个字节表示后面域名的字节数目，紧跟在后面是标识域名的字节数据
    bnd_port: u16,
}

///
/// Socks5 Client side structure
///

/*
   1. Client negotiation request

   The client connects to the server, and sends a version
   identifier/method selection message:

                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |  -> bytes
                   +----+----------+----------+

   If the selected METHOD is X'FF', none of the methods listed by the
   client are acceptable, and the client MUST close the connection.

   The values currently defined for METHOD are:

          o  X'00' NO AUTHENTICATION REQUIRED
          o  X'01' GSSAPI
          o  X'02' USERNAME/PASSWORD
          o  X'03' to X'7F' IANA ASSIGNED
          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
          o  X'FF' NO ACCEPTABLE METHODS
            -- 这是一个特殊的服务端响应值，表示客户端提供的认证方法列表中没有服务端支持的

    假如： 客户端支持无须认证、GSSAPI、U/P， 则nmethods = 3(十进制，因为支持三种认证方法), methods则需要是具体的认证方式列表:
    [x00, x01, x02]

    这些值在服务器返回给客户端的认证响应中也是同样的含义
*/

pub struct s5client_netotiation_request {
    ver: u8,
    nmethods: u8,
    methods: [u8; 255],
}

/*
    3. Client user/password authentication -> send to server  in RFC1929

    This begins with the client producing a
    Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |   -> bytes
           +----+------+----------+------+----------+
*/
pub struct s5client_upw_auth_request {
    ver: u8,
    ulen: u8,
    uname: Vec<u8>, // 需要格外注意其长度是否大于255
    plen: u8,
    passwd: Vec<u8>, // 同上
}

/*
   5. Client send to server with dest_ip, dest_port

   Once the method-dependent subnegotiation has completed, the client
   sends the request details.  If the negotiated method includes
   encapsulation for purposes of integrity checking and/or
   confidentiality, these requests MUST be encapsulated in the method-
   dependent encapsulation.

   The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER            protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV            RESERVED
          o  ATYP           address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT       desired destination port in network octet order
*/

pub struct s5client_2dest_request {
    ver: u8,
    cmd: u8,
    rsv: u8,
    atyp: u8,
    dst_addr: Vec<u8>, // 如果atyp是域名类型，则第一个字节表示域名的长度，后面的是域名字节数据, 注意长度要检查
    dst_port: u16,
}

/* AUTHENTICATION METHODS */
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMethod {
    NoAuth,
    UserPassword,
    // GSSAPI,
    // Custom1(u8),     // 0x80 - 0xFE之间的私有方法定制
    // Custom2(u8),
}

impl AuthMethod {
    pub fn to_byte(&self) -> u8 {
        match self {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::UserPassword => 0x02,
            // AuthMethod::GSSAPI    => 0x01,
            // Custom1
            // Custom2
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(AuthMethod::NoAuth),
            0x02 => Some(AuthMethod::UserPassword),
            // 0x01 => Some(AuthMethod::GSSAPI),
            // Custom1
            // Custom2
            _ => None,
        }
    }
}

// 服务端不支持客户端所列出的所有认证方法时发出这个特殊值
pub const SERVER_NO_ACCEPTABLE_METHOD: u8 = 0xFF;

// Socks5 server默认监听端口
pub const SERVER_DEFAULT_LISTEN_PORT: u16 = 0x438; // == 1080(based decimal)

// Socks5 版本常量
pub const SOCKS5_VERSION: u8 = 0x05;

/* Impl */
impl Default for s5client_netotiation_request {
    /// 至少应该实现无须认证以及用户/密码认证
    /// 应该检查这个长度，只读N个，其中N是方法数量
    fn default() -> Self {
        let methods: [u8; 255] = core::array::from_fn(|ele| match ele {
            0 => AuthMethod::NoAuth.to_byte(),
            1 => AuthMethod::UserPassword.to_byte(),
            _ => 0x00, // 填充值
        });

        s5client_netotiation_request {
            ver: SOCKS5_VERSION,
            nmethods: 0x02,   // 支持的认证方法数量
            methods: methods, // 指明具体支持哪两个认证方法
        }
    }
}

impl s5server_negotiation_resp {
    pub fn new(auth_method: AuthMethod) -> Self {
        s5server_negotiation_resp {
            ver: SOCKS5_VERSION,
            method: auth_method.to_byte(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.method]
    }
}
