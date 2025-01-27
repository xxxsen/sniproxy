package sniproxy

import (
	"sniproxy/resolver"
	"time"
)

type config struct {
	r                   resolver.IResolver
	domainRules         []string
	listenProxyProtocol bool
	dialTimeout         time.Duration
	detectTimeout       time.Duration
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

func WithDialTimeout(t time.Duration) Option {
	return func(c *config) {
		c.dialTimeout = t
	}
}

func WithDetectTimeout(t time.Duration) Option {
	return func(c *config) {
		c.detectTimeout = t
	}
}
