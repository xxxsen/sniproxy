package sniproxy

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xxxsen/common/logutil"
	"github.com/xxxsen/common/trace"
	"go.uber.org/zap"
)

type SNIProxy struct {
	addr    string
	c       *config
	checker *DomainRule
}

func New(addr string, opts ...Option) (*SNIProxy, error) {
	c := &config{}
	for _, opt := range opts {
		opt(c)
	}
	checker := NewDomainRule()
	checker.AddRules(c.domainRules...)
	return &SNIProxy{addr: addr, c: c, checker: checker}, nil
}

func (s *SNIProxy) Start() error {
	ls, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	go s.serveListener(ls)
	return nil
}

func (s *SNIProxy) serveListener(ls net.Listener) {
	pls := &proxyproto.Listener{
		Listener:          ls,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx := context.Background()
	var idx int64 = 1
	for {
		conn, err := pls.Accept()
		if err != nil {
			logutil.GetLogger(ctx).Error("recv connect failed", zap.Error(err))
			time.Sleep(10 * time.Millisecond)
			continue
		}
		logutil.GetLogger(ctx).Debug("recv connection", zap.String("addr", conn.RemoteAddr().String()))
		c := newConnHandler(conn, s)
		newctx := trace.WithTraceId(ctx, strconv.FormatInt(idx, 10))
		idx++
		go c.Serve(newctx)
	}
}
