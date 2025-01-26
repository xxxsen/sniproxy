package resolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDotResolver(t *testing.T) {
	r, err := Make("dot://dns10.quad9.net")
	assert.NoError(t, err)
	ips, err := r.Resolve(context.Background(), "google.com")
	assert.NoError(t, err)
	for _, ip := range ips {
		t.Logf("read ip:%s", ip.String())
	}
}
