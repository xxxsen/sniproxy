package config

import (
	"encoding/json"
	"log"
	"os"
	"sniproxy"
	"sniproxy/constant"

	"github.com/xxxsen/common/logger"
)

type Config struct {
	Bind          string                           `json:"bind"`
	WhiteList     []string                         `json:"whitelist"` //Deprecated: use DomainRule
	Resolver      string                           `json:"resolver"`  //Deprecated: use DomainRule.Resolver
	LogConfig     logger.LogConfig                 `json:"log_config"`
	DialTimeout   int64                            `json:"dial_timeout"`
	DetectTimeout int64                            `json:"detect_timeout"`
	DomainRule    []*sniproxy.DomainRuleItemConfig `json:"domain_rule"`
}

func Parse(f string) (*Config, error) {
	raw, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	c := &Config{
		Bind: ":8443",
		LogConfig: logger.LogConfig{
			Level:   "debug",
			Console: true,
		},
		DialTimeout:   10,
		DetectTimeout: 10,
	}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	for _, item := range c.WhiteList {
		c.DomainRule = append(c.DomainRule, &sniproxy.DomainRuleItemConfig{
			Rule:     item,
			Type:     constant.DomainRuleTypeResolve,
			Resolver: c.Resolver,
		})
	}
	if len(c.WhiteList) > 0 {
		log.Printf("warning: you are using old sni whitelist/resolver config, migrate to DomainRule config plz.")
	}
	c.WhiteList = nil
	return c, nil
}
