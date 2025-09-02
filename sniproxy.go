package sniproxy

import (
	"context"
	"net"
	"sniproxy/domainrule"
	"strconv"
	"time"

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
	checker domainrule.IDomainRule
}

func New(addr string, opts ...Option) (ISNIProxy, error) {
	c := &config{}
	for _, opt := range opts {
		opt(c)
	}
	checker := domainrule.NewDomainRule()
	for _, item := range c.domainRules {
		if err := checker.Add(item.Rule, item); err != nil {
			return nil, err
		}
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
	ctx := context.Background()
	var idx int64 = 1
	for {
		conn, err := ls.Accept()
		if err != nil {
			logutil.GetLogger(ctx).Error("recv connect failed", zap.Error(err))
			time.Sleep(10 * time.Millisecond)
			continue
		}
		newctx := trace.WithTraceId(ctx, strconv.FormatInt(idx, 10))
		idx++
		logutil.GetLogger(newctx).Info("recv connection", zap.String("addr", conn.RemoteAddr().String()))
		c := newConnHandler(conn, s)
		go c.Serve(newctx)
	}
}
