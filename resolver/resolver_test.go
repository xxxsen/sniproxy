package resolver

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUriToParam(t *testing.T) {
	link := "udp://1.2.3.4?enable_ipv4=true&enable_ipv6=false&timeout=5"
	uri, err := url.Parse(link)
	assert.NoError(t, err)
	p, err := uriToDNSParam(uri)
	assert.NoError(t, err)
	assert.True(t, p.EnableIPv4)
	assert.False(t, p.EnableIPv6)
	assert.Equal(t, "1.2.3.4", p.Host)
	assert.Equal(t, "udp", p.Protocol)
	assert.Equal(t, int64(5), p.Timeout)
	t.Logf("data:%+v", *p)
}
