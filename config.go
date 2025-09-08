package sniproxy

import (
	"sniproxy/resolver"
	"time"
)

type DomainRuleItemConfig struct {
	Rule            string `json:"rule,omitempty"`
	DomainRewrite   string `json:"domain_rewrite,omitempty"`
	HTTPPortRewrite uint16 `json:"http_port_rewrite,omitempty"`
	TLSPortRewrite  uint16 `json:"tls_port_rewrite,omitempty"`
	ProxyProtocol   bool   `json:"proxy_protocol,omitempty"`
	Resolver        string `json:"resolver,omitempty"`
}

type DomainRuleItem struct {
	Rule string
	//
	DomainRewrite string
	//
	HTTPPortRewrite uint16
	TLSPortRewrite  uint16
	//
	ProxyProtocol bool
	//
	Resolver resolver.IResolver
}

type config struct {
	domainRules         []*DomainRuleItem
	listenProxyProtocol bool
	dialTimeout         time.Duration
	detectTimeout       time.Duration
}

type Option func(c *config)

func WithAddDomainRule(rule string, data *DomainRuleItem) Option {
	return func(c *config) {
		c.domainRules = append(c.domainRules, data)
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
