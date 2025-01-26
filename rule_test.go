package sniproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRule(t *testing.T) {
	rules := []string{
		"a.com",               //suffix
		"full:x.com",          //full
		"keyword:google",      //keyword
		`regexp:^[a-z]+\.cc$`, //regexp
	}
	r := NewDomainRule()
	err := r.AddRules(rules...)
	assert.NoError(t, err)
	//suffix
	assert.True(t, r.Check("a.com"))
	assert.True(t, r.Check("1.a.com"))
	assert.True(t, r.Check("2.x.a.com"))
	//full
	assert.True(t, r.Check("x.com"))
	assert.False(t, r.Check("2.x.com"))
	assert.False(t, r.Check("2x.com"))
	//keyword
	assert.True(t, r.Check("google.com"))
	assert.True(t, r.Check("zzgoogleccc.com"))
	assert.False(t, r.Check("googl.com"))
	//regexp
	assert.True(t, r.Check("abc.cc"))
	assert.True(t, r.Check("abcd.cc"))
	assert.False(t, r.Check("1.abc.cc"))
	assert.False(t, r.Check("1ab.cc"))
}
