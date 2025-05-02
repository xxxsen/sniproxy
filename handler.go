package sniproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xxxsen/common/iotool"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type connHandler struct {
	conn net.Conn
	svr  *sniproxyImpl
	//中间产物
	sni      string
	port     string
	targetIp string
}

func newConnHandler(conn net.Conn, svr *sniproxyImpl) *connHandler {
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
	logutil.GetLogger(ctx).Info("processs sni proxy succ", zap.String("sni", h.sni),
		zap.String("ip", h.targetIp), zap.String("port", h.port), zap.Duration("cost", time.Since(start)))
}

func (h *connHandler) doResolveTlsTarget(ctx context.Context, r *bufio.Reader) (string, string, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(iotool.NewReadOnlyConn(r), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()
	_ = err
	if hello == nil {
		return "", "", fmt.Errorf("no sni found")
	}
	return hello.ServerName, "443", nil
}

func (h *connHandler) doResolveHTTPTarget(ctx context.Context, r *bufio.Reader) (string, string, error) {
	req, err := http.ReadRequest(r)
	if err != nil {
		return "", "", err
	}
	hostport := strings.TrimSpace(req.Host)
	if len(hostport) == 0 {
		return "", "", fmt.Errorf("no host found")
	}
	host, port, err := net.SplitHostPort(hostport)
	if err == nil {
		return host, port, nil
	}
	return hostport, "80", nil
}

func (h *connHandler) doResolveSNI(ctx context.Context) error {
	_ = h.conn.SetReadDeadline(time.Now().Add(h.svr.c.detectTimeout))
	defer func() {
		_ = h.conn.SetReadDeadline(time.Time{})
	}()

	peekedBytes := new(bytes.Buffer)
	r := io.TeeReader(h.conn, peekedBytes)
	bio := bufio.NewReader(r)
	bs, err := bio.Peek(1)
	if err != nil {
		return fmt.Errorf("read first byte failed, err:%w", err)
	}

	var detecter = h.doResolveTlsTarget

	switch bs[0] {
	case 'G', 'P', 'C', 'H', 'O', 'D', 'T': //HTTP GET/PUT/CONNECT/HEAD/OPTION/DELETE/TRACE
		detecter = h.doResolveHTTPTarget
	}
	domain, port, err := detecter(ctx, bio)
	if err != nil {
		return fmt.Errorf("detect sni failed, err:%w", err)
	}

	r = io.MultiReader(peekedBytes, h.conn)
	h.conn = iotool.WrapConn(h.conn, r, nil, nil)
	h.sni = domain
	h.port = port
	return nil
}

func (h *connHandler) doWhiteListCheck(ctx context.Context) error {
	if !h.svr.checker.Check(h.sni) {
		return fmt.Errorf("sni not in white list, name:%s", h.sni)
	}
	return nil
}

func (h *connHandler) doResolveIP(ctx context.Context) error {
	ips, err := h.svr.c.r.Resolve(ctx, h.sni)
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
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(h.targetIp, h.port), h.svr.c.dialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	return iotool.ProxyStream(ctx, h.conn, conn)
}
