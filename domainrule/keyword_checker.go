package domainrule

import (
	"context"
	"sniproxy/constant"
	"strings"
)

type kwChecker struct {
	kw string
}

func (c kwChecker) IsMatch(ctx context.Context, domain string) (bool, error) {
	return strings.Contains(domain, c.kw), nil
}

func init() {
	Register(constant.DomainTypeKeyword, func(typ, args string) (IDomainRuleChecker, error) {
		return kwChecker{kw: args}, nil
	})
}
