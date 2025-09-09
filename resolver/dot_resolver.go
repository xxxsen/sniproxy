package resolver

import (
    "context"
    "crypto/tls"
    "net"
    "time"
)

func createDotResolver(p *DNSParam) (IPLookuper, error) {
    // Split host and port; default to 853 if port not provided
    host := p.Host
    port := "853"
    if h, prt, err := net.SplitHostPort(p.Host); err == nil {
        host = h
        if prt != "" {
            port = prt
        }
    }

    // Configure dialer and TLS
    var dialer net.Dialer
    dialer.Timeout = time.Duration(p.Timeout) * time.Second

    // Only set ServerName when host is not an IP literal
    serverName := ""
    if ip := net.ParseIP(host); ip == nil {
        serverName = host
    }
    tlsConfig := &tls.Config{
        ServerName:         serverName,
        ClientSessionCache: tls.NewLRUClientSessionCache(32),
        InsecureSkipVerify: false,
    }

    r := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
            addr := net.JoinHostPort(host, port)
            conn, err := dialer.DialContext(ctx, "tcp", addr)
            if err != nil {
                return nil, err
            }
            if tc, ok := conn.(*net.TCPConn); ok {
                _ = tc.SetKeepAlive(p.Keepalive)
                if p.Keepalive && p.KeepaliveTimeout > 0 {
                    _ = tc.SetKeepAlivePeriod(time.Duration(p.KeepaliveTimeout) * time.Second)
                }
            }
            return tls.Client(conn, tlsConfig), nil
        },
    }
    return r, nil
}

func init() {
	Register(SchemaDOT, createDotResolver)
}
