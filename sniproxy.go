package sniproxy

import (
	"context"
	"net"
	"time"

	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type SNIProxy struct {
	addr string
	c    *config
}

func New(addr string, opts ...Option) (*SNIProxy, error) {
	c := &config{}
	for _, opt := range opts {
		opt(c)
	}
	return &SNIProxy{addr: addr, c: c}, nil
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
	ctx := context.Background()
	for {
		conn, err := ls.Accept()
		if err != nil {
			logutil.GetLogger(ctx).Error("recv connect failed", zap.Error(err))
			time.Sleep(10 * time.Millisecond)
			continue
		}
		logutil.GetLogger(ctx).Debug("recv connection", zap.String("addr", conn.RemoteAddr().String()))
		c := newConnHandler(conn, s)
		go c.Serve(ctx)
	}
}
