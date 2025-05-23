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

type ISNIProxy interface {
	Run(ctx context.Context) error
}

type sniproxyImpl struct {
	addr    string
	c       *config
	checker *DomainRule
}

func New(addr string, opts ...Option) (ISNIProxy, error) {
	c := &config{}
	for _, opt := range opts {
		opt(c)
	}
	checker := NewDomainRule()
	if err := checker.AddRules(c.domainRules...); err != nil {
		return nil, err
	}
	return &sniproxyImpl{addr: addr, c: c, checker: checker}, nil
}

func (s *sniproxyImpl) Run(ctx context.Context) error {
	ls, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.serveListener(ls)
	return nil
}

func (s *sniproxyImpl) serveListener(ls net.Listener) {
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
