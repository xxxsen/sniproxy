sniproxy
===

SNI代理, 没啥特殊的, 写这个的目的主要是家里有部分机器不能走透明代理, 但是机器上确实有部分服务是需要科学上网才能访问的, 所以最后就整了这么个代理, 通过DNS劫持, 将部分域名劫持到SNI代理机, 之后SNI代理通过dot解析避免劫持来达到特殊机器通过SNI代理实现科学上网的目的。

**配置:**

```json
{
    "bind": ":8443", //监听地址
    "proxy_protocol": false, //是否从前端接收PROXY protocol(v1/v2)
    "domain_rule": [ //域名规则
        {
            "rule": "full:www.baidu.com", 
            "resolver": "udp://223.5.5.5:53" 
        }
    ]
}
```

**resolver**目前仅支持: tcp/udp/dot 3种协议, 格式为`schema://host:port`, 例如下面这几个

```text
udp://223.5.5.5:53
tcp://223.6.6.6:53
dot://dns10.quad9.net
```

**rule**支持的类型: `full`, `suffix`, `regexp`, `keyword`, 当不填类型, 则使用`suffix`类型
