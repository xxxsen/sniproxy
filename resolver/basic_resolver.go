package resolver

import (
	"context"
	"net"
	"time"
)

func createBasicResolver(p *DNSParam) (IPLookuper, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(p.Timeout) * time.Second,
			}
			return d.DialContext(ctx, network, p.Host)
		},
	}
	return r, nil
}

func init() {
	Register(SchemaTCP, createBasicResolver)
	Register(SchemaUDP, createBasicResolver)
}
