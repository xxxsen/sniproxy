package sniproxy

import (
	"sniproxy/resolver"
	"time"
)

type DomainRuleItem struct {
	Rule        string `json:"domain"`
	Type        string `json:"type"`
	Resolver    string `json:"resolver"`
	MappingName string `json:"mapping_name"`
}

type config struct {
	r                   resolver.IResolver
	domainRules         []*DomainRuleItem
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
