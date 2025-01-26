package main

import (
	"flag"
	"log"
	"sniproxy"
	"sniproxy/config"
	"sniproxy/resolver"

	"github.com/xxxsen/common/logger"
	"go.uber.org/zap"
)

var conf = flag.String("config", "./config.json", "config file")

func main() {
	flag.Parse()
	c, err := config.Parse(*conf)
	if err != nil {
		log.Fatalf("read and decode config failed, file:%s, err:%v", *conf, err)
	}
	log.Printf("read config:%+v", *c)
	logkit := logger.Init(c.LogConfig.File, c.LogConfig.Level, int(c.LogConfig.FileCount), int(c.LogConfig.FileSize), int(c.LogConfig.KeepDays), c.LogConfig.Console)
	r, err := resolver.Make(c.Resolver)
	if err != nil {
		logkit.Fatal("create resolver failed", zap.Error(err), zap.String("resolver_config", c.Resolver))
	}
	pxy, err := sniproxy.New(c.Bind,
		sniproxy.WithResolver(r),
		sniproxy.WithWhiteList(c.WhiteList),
		sniproxy.WithListenProxyProtocol(c.ProxyProtocol),
	)
	if err != nil {
		logkit.Fatal("make sni proxy failed", zap.Error(err))
	}
	if err := pxy.Start(); err != nil {
		logkit.Fatal("start sni proxy failed", zap.Error(err))
	}
	logkit.Info("sni proxy start succ", zap.String("listen", c.Bind))
	select {}
}
