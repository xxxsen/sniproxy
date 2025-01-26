package resolver

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

type IResolver interface {
	Resolve(ctx context.Context, domain string) ([]net.IP, error)
}

type Creator func(uri *url.URL) (IResolver, error)

var mp = make(map[string]Creator)

func Make(link string) (IResolver, error) {
	uri, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	cr, ok := mp[uri.Scheme]
	if !ok {
		return nil, fmt.Errorf("resolver schema:%s not support", uri.Scheme)
	}
	return cr(uri)
}

func Register(schema string, cr Creator) {
	mp[schema] = cr
}
