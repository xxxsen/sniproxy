package config

import (
	"encoding/json"
	"os"

	"github.com/xxxsen/common/logger"
)

type Config struct {
	Bind          string           `json:"bind"`
	ProxyProtocol bool             `json:"proxy_protocol"`
	WhiteList     []string         `json:"whitelist"`
	Resolver      string           `json:"resolver"`
	LogConfig     logger.LogConfig `json:"log_config"`
	DialTimeout   int64            `json:"dial_timeout"`
	DetectTimeout int64            `json:"detect_timeout"`
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
