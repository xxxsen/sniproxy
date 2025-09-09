package resolver

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestBasicResolver(t *testing.T) {
    cases := []string{
        "tcp://223.5.5.5:53", // explicit port
        "tcp://223.5.5.5",    // implicit port 53
        "udp://223.5.5.5:53", // explicit port
        "udp://223.5.5.5",    // implicit port 53
    }
    for _, link := range cases {
        t.Run(link, func(t *testing.T) {
            r, err := Make(link)
            assert.NoError(t, err)
            ctx := context.Background()
            ips, err := r.Resolve(ctx, "example.com")
            assert.NoError(t, err)
            assert.NotEmpty(t, ips)
            for _, ip := range ips {
                t.Logf("%s => ip:%s", link, ip.String())
            }
        })
    }
}
