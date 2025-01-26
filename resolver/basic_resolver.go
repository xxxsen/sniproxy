package resolver

import (
	"context"
	"net"
	"net/url"
	"time"
)

type basicResolver struct {
	r *net.Resolver
}

func (r *basicResolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	ips, err := r.r.LookupIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func createBasicResolver(uri *url.URL) (IResolver, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 10 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}
	return &basicResolver{r: r}, nil
}

func init() {
	Register(SchemaTCP, createBasicResolver)
	Register(SchemaUDP, createBasicResolver)
}
