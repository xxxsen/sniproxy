package main

import (
	"context"
	"flag"
	"log"
	"sniproxy"
	"sniproxy/config"
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
	r, err := resolver.Make(c.Resolver)
	if err != nil {
		logkit.Fatal("create resolver failed", zap.Error(err), zap.String("resolver_config", c.Resolver))
	}
	pxy, err := sniproxy.New(c.Bind,
		sniproxy.WithResolver(r),
		sniproxy.WithWhiteList(c.WhiteList),
		sniproxy.WithListenProxyProtocol(c.ProxyProtocol),
		sniproxy.WithDialTimeout(time.Duration(c.DialTimeout)*time.Second),
		sniproxy.WithDetectTimeout(time.Duration(c.DetectTimeout)*time.Second),
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
