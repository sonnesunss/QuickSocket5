# Intro

Socks5是一个网络传输协议，其主要描述了客户端与外部网络之间进行通讯时应该遵守的规则.

大致通讯流程如下:

> Socks5 Client <==> Socks5 Server <==> Remote Server

```mermaid
graph TD
    A[Socks5 Client] -->|1. 发起连接 | B[SOCKS5 Server]
    B -->|2. 协商认证方法| A
    A -->|3. 提供认证信息（如需要）| B
    B -->|4. 认证通过| A
    A -->|5. 发送目标地址和端口| B
    B -->|6. 建立与目标服务器连接| C[Dest server]
    B -->|7. 通知客户端连接状态| A
    A -->|8. 数据传输| B
    B -->|9. 转发数据| C
    C -->|10. 返回数据| B
    B -->|11. 转发数据| A
```

## Socks5 Protocl RFC

1. [SOCKS Protocol Version 5](./rfc1928.txt)
2. [Username/Password Authentication for SOCKS V5](./rfc1929.txt)
