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
	"sniproxy/constant"
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
	sni        string
	port       string
	nextTarget string
}

func newConnHandler(conn net.Conn, svr *sniproxyImpl) *connHandler {
	return &connHandler{conn: conn, svr: svr}
}

func (h *connHandler) Serve(ctx context.Context) {
	defer func() {
		_ = h.conn.Close()
	}()
	handlers := []struct {
		name string
		fn   func(ctx context.Context) error
	}{
		{"resolve_sni", h.doResolveSNI},
		{"rule_handle", h.doRuleHandle},
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
		zap.String("next_target", h.nextTarget), zap.String("port", h.port), zap.Duration("cost", time.Since(start)))
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

func (h *connHandler) doRuleHandle(ctx context.Context) error {
	data, ok := h.svr.checker.Check(h.sni)
	if !ok {
		return fmt.Errorf("sni not in white list, name:%s", h.sni)
	}
	ruleData := data.(*DomainRuleItem)
	logutil.GetLogger(ctx).Debug("domain match rule", zap.String("domain", h.sni),
		zap.String("rule", ruleData.Rule), zap.String("rule_type", ruleData.Type))
	switch ruleData.Type {
	case constant.DomainRuleTypeResolve:
		ips, err := ruleData.Resolver.Resolve(ctx, h.sni)
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			return fmt.Errorf("no ip link with domain")
		}
		h.nextTarget = ips[rand.Int()%len(ips)].String()
	case constant.DomainRuleTypeMapping:
		h.nextTarget = ruleData.MappingName
	default:
		return fmt.Errorf("no rule type to handle, type:%s", ruleData.Type)
	}
	return nil
}

func (h *connHandler) doProxy(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(h.nextTarget, h.port), h.svr.c.dialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	return iotool.ProxyStream(ctx, h.conn, conn)
}
