package resolver

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/gorilla/schema"
	lru "github.com/hnlq715/golang-lru"
)

type IResolver interface {
	Resolve(ctx context.Context, domain string) ([]net.IP, error)
}

type DNSParam struct {
	Protocol         string `schema:"-"`
	Host             string `schema:"-"`
	Timeout          int64  `schema:"timeout"`
	EnableIPv4       bool   `schema:"enable_ipv4"`
	EnableIPv6       bool   `schema:"enable_ipv6"`
	Keepalive        bool   `schema:"keepalive"`
	KeepaliveTimeout int64  `schema:"keepalive_timeout"`
	CacheTTL         int64  `schema:"cache_ttl"`
	CacheSize        int64  `schema:"cache_size"`
}

type Creator func(p *DNSParam) (*net.Resolver, error)

var mp = make(map[string]Creator)

func uriToDNSParam(uri *url.URL) (*DNSParam, error) {
	p := &DNSParam{
		Timeout:          10,
		Protocol:         uri.Scheme,
		Host:             uri.Host,
		EnableIPv4:       true,
		EnableIPv6:       false,
		Keepalive:        true,
		KeepaliveTimeout: 10 * 60,
		CacheTTL:         300,
		CacheSize:        1000,
	}
	dec := schema.NewDecoder()
	if err := dec.Decode(p, uri.Query()); err != nil {
		return nil, err
	}
	return p, nil
}

func Make(link string) (IResolver, error) {
	uri, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	cr, ok := mp[uri.Scheme]
	if !ok {
		return nil, fmt.Errorf("resolver schema:%s not support", uri.Scheme)
	}
	param, err := uriToDNSParam(uri)
	if err != nil {
		return nil, err
	}
	r, err := cr(param)
	if err != nil {
		return nil, err
	}
	return newDefaultResolver(r, param)
}

func Register(schema string, cr Creator) {
	mp[schema] = cr
}

type defaultResolver struct {
	r     *net.Resolver
	param *DNSParam
	c     *lru.Cache
}

func (r *defaultResolver) makeCacheKey(nettype string, domain string) string {
	return fmt.Sprintf("cache:%s:%s", nettype, domain)
}

func (r *defaultResolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	nettype, err := r.resolveNetworkType(r.param.EnableIPv4, r.param.EnableIPv6)
	if err != nil {
		return nil, err
	}
	loader := func(ctx context.Context) ([]net.IP, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(r.param.Timeout)*time.Second)
		defer cancel()
		return r.r.LookupIP(ctx, nettype, domain)
	}
	cacheKey := r.makeCacheKey(nettype, domain)
	if res, ok := r.c.Get(cacheKey); ok {
		return res.([]net.IP), nil
	}
	res, err := loader(ctx)
	if err != nil {
		return nil, err
	}
	if r.param.CacheTTL > 0 {
		r.c.AddEx(cacheKey, res, time.Duration(r.param.CacheTTL)*time.Second)
	}
	return res, nil
}

func (r *defaultResolver) resolveNetworkType(enablev4, enablev6 bool) (string, error) {
	if !(enablev4 || enablev6) {
		return "", fmt.Errorf("unable to resolve network type")
	}
	if enablev4 && !enablev6 {
		return "ip4", nil
	}
	if !enablev4 && enablev6 {
		return "ip6", nil
	}
	return "ip", nil
}

func newDefaultResolver(r *net.Resolver, p *DNSParam) (IResolver, error) {
	c, err := lru.New(int(p.CacheSize))
	if err != nil {
		return nil, err
	}
	return &defaultResolver{
		r:     r,
		param: p,
		c:     c,
	}, nil
}
