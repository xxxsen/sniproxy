package sniproxy

import (
	"sniproxy/resolver"
	"time"
)

type DomainRuleItemConfig struct {
	Rule        string `json:"rule,omitempty"`
	Type        string `json:"type,omitempty"`
	Resolver    string `json:"resolver,omitempty"`
	MappingName string `json:"mapping_name,omitempty"`
}

type DomainRuleItem struct {
	Rule        string
	Type        string
	Resolver    resolver.IResolver
	MappingName string
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
