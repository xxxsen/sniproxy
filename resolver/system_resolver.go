package resolver

import (
	"net"
)

func createSystemResolver(p *DNSParam) (*net.Resolver, error) {
	// 使用系统默认的resolver，不需要自定义Dial函数
	r := &net.Resolver{}
	return r, nil
}

func init() {
	Register(SchemaSystem, createSystemResolver)
}
