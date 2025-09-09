package domainrule

import (
	"context"
	"strings"

	"github.com/xxxsen/sniproxy/constant"
)

type suffixChecker struct {
	suffix string
}

func (c suffixChecker) IsMatch(ctx context.Context, domain string) (bool, error) {
	return strings.HasSuffix(domain, c.suffix), nil
}

func init() {
	Register(constant.DomainTypeSuffix, func(typ, args string) (IDomainRuleChecker, error) {
		return suffixChecker{suffix: args}, nil
	})
}
