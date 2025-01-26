package sniproxy

import "sniproxy/resolver"

type config struct {
	r                   resolver.IResolver
	domainRules         []string
	listenProxyProtocol bool
}

type Option func(c *config)

func WithResolver(r resolver.IResolver) Option {
	return func(c *config) {
		c.r = r
	}
}

func WithWhiteList(list []string) Option {
	return func(c *config) {
		c.domainRules = list
	}
}

func WithListenProxyProtocol(v bool) Option {
	return func(c *config) {
		c.listenProxyProtocol = v
	}
}
