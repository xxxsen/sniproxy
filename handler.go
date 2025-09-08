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
	"strconv"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xxxsen/common/iotool"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type connHandler struct {
	conn net.Conn
	svr  *sniproxyImpl
	//中间产物
	ruleData   *DomainRuleItem
	isTLS      bool
	sni        string
	port       string
	nextTarget string
	//
	remote net.Conn
}

func newConnHandler(conn net.Conn, svr *sniproxyImpl) *connHandler {
	return &connHandler{conn: conn, svr: svr}
}

func (h *connHandler) Serve(ctx context.Context) {
	defer func() {
		_ = h.conn.Close()
		if h.remote != nil {
			_ = h.remote.Close()
		}
	}()
	handlers := []struct {
		name string
		fn   func(ctx context.Context) error
	}{
		{"resolve_sni", h.doResolveSNI},
		{"rule_check", h.doRuleCheck},
		{"dns_resolve", h.doDNSResolve},
		{"port_rewrite", h.doPortRewrite},
		{"dial_remote", h.doDialRemote},
		{"proxy_protocol", h.doProxyProtocol},
		{"proxy_request", h.doProxy},
	}
	start := time.Now()
	for _, step := range handlers {
		stepStart := time.Now()
		if err := step.fn(ctx); err != nil {
			logutil.GetLogger(ctx).Error("process step failed", zap.Error(err), zap.String("step", step.name))
			return
		}
		logutil.GetLogger(ctx).Debug("process step succ", zap.String("step", step.name), zap.Duration("cost", time.Since(stepStart)))
	}
	logutil.GetLogger(ctx).Info("processs sni proxy succ", zap.String("sni", h.sni), zap.Bool("is_tls", h.isTLS),
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
	var detecter func(ctx context.Context, r *bufio.Reader) (string, string, error)s
	switch bs[0] {
	case 'G', 'P', 'C', 'H', 'O', 'D', 'T': //HTTP GET/PUT/CONNECT/HEAD/OPTION/DELETE/TRACE
		detecter = h.doResolveHTTPTarget
	default:
		detecter = h.doResolveTlsTarget
		h.isTLS = true
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

func (h *connHandler) doRuleCheck(ctx context.Context) error {
	data, ok, err := h.svr.checker.Check(ctx, h.sni)
	if err != nil {
		return fmt.Errorf("check rule failed, err:%w", err)
	}
	if !ok {
		return fmt.Errorf("sni not in white list, name:%s", h.sni)
	}
	h.ruleData = data.(*DomainRuleItem)
	return nil
}

func (h *connHandler) doDNSResolve(ctx context.Context) error {
	logutil.GetLogger(ctx).Debug("domain match rule", zap.String("domain", h.sni), zap.String("rewrite", h.ruleData.DomainRewrite),
		zap.String("rule", h.ruleData.Rule))

	domain := h.sni
	if len(h.ruleData.DomainRewrite) > 0 {
		domain = h.ruleData.DomainRewrite
	}
	ips, err := h.ruleData.Resolver.Resolve(ctx, domain)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("no ip link with domain")
	}
	h.nextTarget = ips[rand.Int()%len(ips)].String()
	return nil
}

func (h *connHandler) doPortRewrite(ctx context.Context) error {
	if h.ruleData.TLSPortRewrite > 0 && h.isTLS {
		logutil.GetLogger(ctx).Debug("rewrite tls port", zap.String("old_port", h.port), zap.Uint16("new_port", h.ruleData.TLSPortRewrite))
		h.port = strconv.FormatUint(uint64(h.ruleData.TLSPortRewrite), 10)
	}
	if h.ruleData.HTTPPortRewrite > 0 && !h.isTLS {
		logutil.GetLogger(ctx).Debug("rewrite http port", zap.String("old_port", h.port), zap.Uint16("new_port", h.ruleData.HTTPPortRewrite))
		h.port = strconv.FormatUint(uint64(h.ruleData.HTTPPortRewrite), 10)
	}
	return nil
}

func (h *connHandler) doDialRemote(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(h.nextTarget, h.port), h.svr.c.dialTimeout)
	if err != nil {
		return err
	}
	h.remote = conn
	return nil
}

func (h *connHandler) doProxyProtocol(ctx context.Context) error {
	if !h.ruleData.ProxyProtocol {
		return nil
	}
	hdr := proxyproto.HeaderProxyFromAddrs(0, h.conn.RemoteAddr(), h.conn.LocalAddr())
	if _, err := hdr.WriteTo(h.remote); err != nil {
		return fmt.Errorf("write proxy protocol failed, err:%w", err)
	}
	return nil
}

func (h *connHandler) doProxy(ctx context.Context) error {
	return iotool.ProxyStream(ctx, h.conn, h.remote)
}
