package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sniproxy"
	"sniproxy/config"
	"sniproxy/constant"
	"sniproxy/resolver"
	"time"

	"github.com/xxxsen/common/logger"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

var conf = flag.String("config", "./config.json", "config file")

func main() {
	flag.Parse()
	c, err := config.Parse(*conf)
	if err != nil {
		log.Fatalf("read and decode config failed, file:%s, err:%v", *conf, err)
	}
	logkit := logger.Init(c.LogConfig.File, c.LogConfig.Level, int(c.LogConfig.FileCount), int(c.LogConfig.FileSize), int(c.LogConfig.KeepDays), c.LogConfig.Console)
	logkit.Info("read config", zap.Any("config", *c))
	opts := []sniproxy.Option{
		sniproxy.WithListenProxyProtocol(c.ProxyProtocol),
		sniproxy.WithDialTimeout(time.Duration(c.DialTimeout) * time.Second),
		sniproxy.WithDetectTimeout(time.Duration(c.DetectTimeout) * time.Second),
	}
	for _, dr := range c.DomainRule {
		dritem, err := makeDomainRule(dr)
		if err != nil {
			logkit.Fatal("make domain rule option failed", zap.Error(err), zap.String("domain_rule", dr.Rule))
		}
		opts = append(opts, sniproxy.WithAddDomainRule(dr.Rule, dritem))
	}
	pxy, err := sniproxy.New(c.Bind,
		opts...,
	)
	if err != nil {
		logkit.Fatal("make sni proxy failed", zap.Error(err))
	}
	ctx := context.Background()
	logutil.GetLogger(ctx).Info("init sni proxy succ, start it...")
	if err := pxy.Run(ctx); err != nil {
		logkit.Fatal("start sni proxy failed", zap.Error(err))
	}
}

func makeDomainRule(dr *sniproxy.DomainRuleItemConfig) (*sniproxy.DomainRuleItem, error) {
	var r resolver.IResolver
	var err error
	if dr.Type == constant.DomainRuleTypeResolve {
		if len(dr.Resolver) == 0 {
			return nil, fmt.Errorf("no resolver found")
		}
		r, err = resolver.Make(dr.Resolver)
		if err != nil {
			return nil, fmt.Errorf("make resolver failed, err:%w", err)
		}
	}

	return &sniproxy.DomainRuleItem{
		Rule:        dr.Rule,
		Type:        dr.Type,
		Resolver:    r,
		MappingName: dr.MappingName,
	}, nil
}
