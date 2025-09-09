package domainrule

import (
	"context"

	"github.com/xxxsen/sniproxy/constant"
)

type fullNameChecker struct {
	name string
}

func (c fullNameChecker) IsMatch(ctx context.Context, domain string) (bool, error) {
	return c.name == domain, nil
}

func init() {
	Register(constant.DomainTypeFull, func(typ, args string) (IDomainRuleChecker, error) {
		return fullNameChecker{name: args}, nil
	})
}
