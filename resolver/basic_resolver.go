package resolver

import (
	"context"
	"net"
	"time"
)

func createBasicResolver(p *DNSParam) (*net.Resolver, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(p.Timeout) * time.Second,
			}
			address = p.Host
			return d.DialContext(ctx, network, address)
		},
	}
	return r, nil
}

func init() {
	Register(SchemaTCP, createBasicResolver)
	Register(SchemaUDP, createBasicResolver)
}
