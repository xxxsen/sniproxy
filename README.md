sniproxy
===

一个基于 Go 的四层域名代理。它会在收到连接后优先识别 TLS SNI 或 HTTP `Host`，按域名规则选择目标，再完成 DNS 解析、端口改写和 TCP 转发。

适合的场景：

- 按域名白名单转发 HTTPS 或 HTTP 流量
- 为不同域名指定不同的 DNS resolver
- 在转发前按规则做域名重写、端口重写
- 在监听端或转发端启用 PROXY protocol

## 特性

- 支持 TLS SNI 和 HTTP/1.x `Host` 识别
- 支持 4 类域名规则：`suffix`、`full`、`keyword`、`regexp`
- 支持每条规则绑定独立 resolver
- 支持目标域名重写、HTTP/TLS 端口重写
- 支持监听端接收 PROXY protocol，或向后端发送 PROXY protocol
- 支持来源 IP 白名单控制
- 内置 DNS 缓存与超时控制

## 工作流程

每个连接会按下面的顺序处理：

1. 识别请求目标
   TLS 连接读取 SNI，HTTP 连接读取 `Host`
2. 匹配域名规则
   规则按配置顺序生效，命中第一条后立即停止继续匹配
3. 检查来源 IP 白名单
4. 使用规则绑定的 resolver 解析目标 IP
5. 根据协议执行端口重写
6. 连接目标并开始转发
7. 如启用，向后端写入 PROXY protocol

## 快速开始

1. 准备配置文件 `config.json`
2. 启动服务

```bash
go run ./cmd -config ./config.json
```

也可以先构建再运行：

```bash
go build -o sniproxy ./cmd
./sniproxy -config ./config.json
```

## 配置示例

下面是一份更接近实际使用的配置：

```json
{
  "bind": ":8443",
  "dial_timeout": 10,
  "detect_timeout": 10,
  "proxy_protocol": false,
  "log_config": {
    "level": "debug",
    "console": true
  },
  "domain_rule": [
    {
      "rule": "suffix:google.com",
      "resolver": "dot://dns10.quad9.net?timeout=5&cache_ttl=300&cache_size=1000",
      "tls_port_rewrite": 443
    },
    {
      "rule": "full:svc.example.com",
      "domain_rewrite": "origin.internal.example.com",
      "resolver": "system://",
      "proxy_protocol": true,
      "white_list": [
        "10.0.0.0/8",
        "192.168.0.0/16",
        "127.0.0.1/32"
      ]
    },
    {
      "rule": "regexp:^api\\d+\\.example\\.com$",
      "resolver": "tcp://1.1.1.1:53?enable_ipv4=true&enable_ipv6=false",
      "http_port_rewrite": 8080
    }
  ]
}
```

## 顶层配置

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `bind` | string | `:8443` | 监听地址 |
| `dial_timeout` | int | `10` | 连接后端超时，单位秒 |
| `detect_timeout` | int | `10` | 识别 TLS/HTTP 目标超时，单位秒 |
| `proxy_protocol` | bool | `false` | 是否在监听端接收 PROXY protocol |
| `log_config` | object | 见下 | 日志配置 |
| `domain_rule` | array | `[]` | 域名规则列表，按顺序匹配 |

`log_config` 默认值：

```json
{
  "level": "debug",
  "console": true
}
```

## 规则配置

每个 `domain_rule` 支持以下字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `rule` | string | 是 | 匹配规则 |
| `resolver` | string | 否 | 解析器 URI；为空时默认 `system://` |
| `domain_rewrite` | string | 否 | 解析前将请求域名改写为新域名 |
| `http_port_rewrite` | uint16 | 否 | 命中 HTTP 时改写目标端口 |
| `tls_port_rewrite` | uint16 | 否 | 命中 TLS 时改写目标端口 |
| `proxy_protocol` | bool | 否 | 是否向后端发送 PROXY protocol |
| `white_list` | array | 否 | 允许访问该规则的来源 IP / CIDR 列表 |

### 规则类型

支持以下规则类型：

| 类型 | 示例 | 说明 |
| --- | --- | --- |
| `suffix` | `suffix:google.com` | 后缀匹配；`google.com` 也可简写为 `google.com` |
| `full` | `full:svc.example.com` | 完整匹配 |
| `keyword` | `keyword:google` | 包含匹配 |
| `regexp` | `regexp:^api\\d+\\.example\\.com$` | 正则匹配 |

注意：

- 未显式写类型时，默认按 `suffix` 处理
- 规则按配置顺序匹配，第一条命中即返回
- 更具体的规则如果放在更泛的规则后面，可能永远不会命中

## Resolver URI

支持以下 resolver：

| URI | 说明 |
| --- | --- |
| `system://` | 使用系统 resolver |
| `udp://1.1.1.1` | 使用 UDP DNS，默认端口 `53` |
| `tcp://8.8.8.8:53` | 使用 TCP DNS |
| `dot://dns10.quad9.net` | 使用 DNS over TLS，默认端口 `853` |

resolver 支持的常用查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `timeout` | `10` | DNS 查询超时，单位秒 |
| `enable_ipv4` | `true` | 是否查询 IPv4 |
| `enable_ipv6` | `false` | 是否查询 IPv6 |
| `keepalive` | `true` | 是否启用长连接 |
| `keepalive_timeout` | `600` | keepalive 周期，单位秒 |
| `cache_ttl` | `300` | DNS 缓存 TTL，单位秒 |
| `cache_size` | `1000` | DNS 缓存条目数 |

示例：

```text
system://
udp://1.1.1.1?timeout=3&cache_ttl=60
tcp://8.8.8.8:53?enable_ipv4=true&enable_ipv6=false
dot://dns10.quad9.net?timeout=5&keepalive=true
```

## Docker

镜像可以直接从仓库构建：

```bash
docker build -t sniproxy .
docker run --rm -p 8443:8443 -v "$(pwd)/config.json:/config.json:ro" sniproxy -config /config.json
```

## 限制与注意事项

- 当前只识别 TLS 和 HTTP/1.x，请求如果既不是这两类协议，将按 TLS 路径尝试识别
- 转发目标是解析得到的 IP，后端连接不会再次基于域名发起请求
- `dot://` 建议使用主机名而不是裸 IP，便于 TLS `ServerName` 校验
- 开启监听端 `proxy_protocol` 后，应确保前置负载均衡或代理来源可信
- 如果某条规则设置了 `white_list`，来源 IP 不在名单内时会直接拒绝

## 测试

```bash
go test ./...
```
