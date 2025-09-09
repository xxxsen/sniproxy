package config

import (
	"encoding/json"
	"os"
	"sniproxy"

	"github.com/xxxsen/common/logger"
)

type Config struct {
	Bind          string           `json:"bind"`
	LogConfig     logger.LogConfig `json:"log_config"`
	DialTimeout   int64            `json:"dial_timeout"`
	DetectTimeout int64            `json:"detect_timeout"`
	// When true, the server listens with PROXY protocol support (v1/v2)
	ProxyProtocol bool                             `json:"proxy_protocol"`
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
	return c, nil
}
