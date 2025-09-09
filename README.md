sniproxy
===

## 简介
- 一个简单的 SNI 代理：按域名白名单转发 TCP 流量，解析可走 DoT，支持监听端/转发端的 PROXY protocol。

## 快速开始
- 准备配置文件 `config.json`（见下例）
- 启动：`go run ./cmd -config ./config.json`

## 配置示例
```json
{
  "bind": ":8443",
  "proxy_protocol": false,
  "dial_timeout": 10,
  "detect_timeout": 10,
  "domain_rule": [
    { "rule": "suffix:google.com", "resolver": "dot://dns10.quad9.net", "tls_port_rewrite": 443 },
    { "rule": "full:svc.example.com", "resolver": "system://", "proxy_protocol": true }
  ]
}
```
## 字段速查
- 顶层：`bind`、`proxy_protocol`、`dial_timeout`、`detect_timeout`、`domain_rule`
- 规则：`rule`、`resolver`、`domain_rewrite`、`http_port_rewrite`、`tls_port_rewrite`、`proxy_protocol`

## Resolver
- `system://`、`udp://host[:53]`、`tcp://host[:53]`、`dot://host[:853]`
- 可选参数：`timeout`、`enable_ipv4`、`enable_ipv6`、`cache_ttl`、`cache_size` 等

## 规则类型
- `full`、`suffix`、`keyword`、`regexp`（不写类型时默认 `suffix`）

## 注意事项
- 仅识别 TLS 与 HTTP/1.x
- DoT 建议使用主机名（避免证书校验问题）
- 启用监听端 PROXY 后限制上游来源（防止伪造）

## 测试
```bash
go test ./resolver -v
```
