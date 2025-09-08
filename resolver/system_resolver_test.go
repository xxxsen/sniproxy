package resolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSystemResolver(t *testing.T) {
	r, err := Make("system://")
	assert.NoError(t, err)
	ctx := context.Background()
	ips, err := r.Resolve(ctx, "example.com")
	assert.NoError(t, err)
	for _, ip := range ips {
		t.Logf("ip:%s", ip.String())
	}
}
