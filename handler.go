package sniproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/xxxsen/common/iotool"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type connHandler struct {
	conn net.Conn
	svr  *SNIProxy
	//中间产物
	sni      *tls.ClientHelloInfo
	targetIp string
}

func newConnHandler(conn net.Conn, svr *SNIProxy) *connHandler {
	return &connHandler{conn: conn, svr: svr}
}

func (h *connHandler) Serve(ctx context.Context) {
	defer func() {
		h.conn.Close()
	}()
	handlers := []struct {
		name string
		fn   func(ctx context.Context) error
	}{
		{"resolve_sni", h.doResolveSNI},
		{"check_whitelist", h.doWhiteListCheck},
		{"resolve_ip", h.doResolveIP},
		{"proxy_request", h.doProxy},
	}
	start := time.Now()
	for _, step := range handlers {
		stepStart := time.Now()
		if err := step.fn(ctx); err != nil {
			logutil.GetLogger(ctx).Error("process sni step failed", zap.Error(err), zap.String("step", step.name))
			return
		}
		logutil.GetLogger(ctx).Debug("process sni step succ", zap.String("step", step.name), zap.Duration("cost", time.Since(stepStart)))
	}
	logutil.GetLogger(ctx).Info("processs sni proxy succ", zap.String("sni", h.sni.ServerName),
		zap.String("target_ip", h.targetIp), zap.Duration("cost", time.Since(start)))
}

func (h *connHandler) doResolveSNI(ctx context.Context) error {
	peekedBytes := new(bytes.Buffer)
	tr := io.TeeReader(h.conn, peekedBytes)

	var hello *tls.ClientHelloInfo
	err := tls.Server(iotool.NewReadOnlyConn(tr), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()
	_ = err
	if hello == nil {
		return fmt.Errorf("no sni found")
	}
	r := io.MultiReader(peekedBytes, h.conn)
	h.conn = iotool.WrapConn(h.conn, r, nil, nil)
	h.sni = hello
	return nil
}

func (h *connHandler) doWhiteListCheck(ctx context.Context) error {
	if !h.svr.checker.Check(h.sni.ServerName) {
		return fmt.Errorf("sni not in white list")
	}
	return nil
}

func (h *connHandler) doResolveIP(ctx context.Context) error {
	ips, err := h.svr.c.r.Resolve(ctx, h.sni.ServerName)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("no ip link with domain")
	}
	h.targetIp = ips[rand.Int()%len(ips)].String()
	return nil
}

func (h *connHandler) doProxy(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", h.targetIp), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return iotool.ProxyStream(ctx, h.conn, conn)
}
