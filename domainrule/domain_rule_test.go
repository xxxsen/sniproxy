package domainrule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testRule struct {
	domain string
	ok     bool
}

func TestRule(t *testing.T) {
	rules := map[string][]testRule{
		"a.com": []testRule{
			{
				domain: "a.com",
				ok:     true,
			},
			{
				domain: "1.a.com",
				ok:     true,
			},
			{
				domain: "2.x.a.com",
				ok:     true,
			},
		}, //suffix
		"full:x.com": []testRule{
			{
				domain: "x.com",
				ok:     true,
			},
			{
				domain: "2.x.com",
				ok:     false,
			},
			{
				domain: "2x.com",
				ok:     false,
			},
		}, //full
		"keyword:google": []testRule{
			{
				domain: "google.com",
				ok:     true,
			},
			{
				domain: "zzgoogleccc.com",
				ok:     true,
			},
			{
				domain: "googl.com",
				ok:     false,
			},
		}, //keyword
		`regexp:^[a-z]+\.cc$`: []testRule{
			{
				domain: "abc.cc",
				ok:     true,
			},
			{
				domain: "abcd.cc",
				ok:     true,
			},
			{
				domain: "1.abc.cc",
				ok:     false,
			},
			{
				domain: "1ab.cc",
				ok:     false,
			},
		}, //regexp
	}
	dr := NewDomainRule()
	for rule, testRuleList := range rules {
		err := dr.Add(rule, nil)
		assert.NoError(t, err)
		for _, item := range testRuleList {
			_, ok, _ := dr.Check(context.Background(), item.domain)
			assert.Equal(t, ok, item.ok)
		}
	}
}

func TestOrder(t *testing.T) {
	dr := NewDomainRule()
	dr.Add("suffix:a.com", 1)
	dr.Add("full:1.a.com", 2)
	v, ok, err := dr.Check(context.Background(), "1.a.com")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 1, v)
}
