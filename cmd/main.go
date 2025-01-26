package main

import (
	"context"
	"flag"
	"log"
	"sniproxy"
	"sniproxy/config"
	"sniproxy/resolver"

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
	log.Printf("read config:%+v", *c)
	ctx := context.Background()
	r, err := resolver.Make(c.Resolver)
	if err != nil {
		logutil.GetLogger(ctx).Fatal("create resolver failed", zap.Error(err), zap.String("resolver_config", c.Resolver))
	}
	if len(c.WhiteList) == 0 {
		logutil.GetLogger(ctx).Warn("no whitelist found, will proxy all trafic")
	}
	pxy, err := sniproxy.New(c.Bind, sniproxy.WithResolver(r), sniproxy.WithWhiteList(c.WhiteList))
	if err != nil {
		logutil.GetLogger(ctx).Fatal("make sni proxy failed", zap.Error(err))
	}
	if err := pxy.Start(); err != nil {
		logutil.GetLogger(ctx).Fatal("start sni proxy failed", zap.Error(err))
	}
	logutil.GetLogger(ctx).Info("sni proxy start succ", zap.String("listen", c.Bind))
	select {}
}
