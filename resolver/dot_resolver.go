package resolver

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

func createDotResolver(p *DNSParam) (*net.Resolver, error) {
	var dialer net.Dialer
	tlsConfig := &tls.Config{
		ServerName:         p.Host,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
		InsecureSkipVerify: false,
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(context context.Context, _, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(context, "tcp", p.Host+":853")
			if err != nil {
				return nil, err
			}

			_ = conn.(*net.TCPConn).SetKeepAlive(p.Keepalive)
			_ = conn.(*net.TCPConn).SetKeepAlivePeriod(time.Duration(p.KeepaliveTimeout) * time.Second)
			return tls.Client(conn, tlsConfig), nil
		},
	}
	return r, nil
}

func init() {
	Register(SchemaDOT, createDotResolver)
}
