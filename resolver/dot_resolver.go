package resolver

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"
)

type dotResolver struct {
	r *net.Resolver
}

func (r *dotResolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	return r.r.LookupIP(ctx, "ip4", domain)
}

func createDotResolver(uri *url.URL) (IResolver, error) {
	var dialer net.Dialer
	tlsConfig := &tls.Config{
		ServerName:         uri.Host,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),

		InsecureSkipVerify: false,
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(context context.Context, _, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(context, "tcp", uri.Host+":853")
			if err != nil {
				return nil, err
			}

			_ = conn.(*net.TCPConn).SetKeepAlive(true)
			_ = conn.(*net.TCPConn).SetKeepAlivePeriod(10 * time.Minute)
			return tls.Client(conn, tlsConfig), nil
		},
	}
	return &dotResolver{r: r}, nil
}

func init() {
	Register(SchemaDOT, createDotResolver)
}
