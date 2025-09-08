package resolver

import (
    "context"
    "net"
    "time"
)

func createBasicResolver(p *DNSParam) (IPLookuper, error) {
    // Split host and port from p.Host. Default DNS port to 53 when absent.
    host := p.Host
    port := "53"
    if h, prt, err := net.SplitHostPort(p.Host); err == nil {
        host = h
        if prt != "" {
            port = prt
        }
    }

    r := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
            d := net.Dialer{
                Timeout: time.Duration(p.Timeout) * time.Second,
            }
            return d.DialContext(ctx, network, net.JoinHostPort(host, port))
        },
    }
    return r, nil
}

func init() {
	Register(SchemaTCP, createBasicResolver)
	Register(SchemaUDP, createBasicResolver)
}
