package domainrule

import (
	"context"
	"regexp"
	"sniproxy/constant"
)

type regexpChecker struct {
	re *regexp.Regexp
}

func (c regexpChecker) IsMatch(ctx context.Context, domain string) (bool, error) {
	if c.re.MatchString(domain) {
		return true, nil
	}
	return false, nil
}

func init() {
	Register(constant.DomainTypeRegexp, func(typ, args string) (IDomainRuleChecker, error) {
		re, err := regexp.Compile(args)
		if err != nil {
			return nil, err
		}
		return regexpChecker{re: re}, nil
	})
}
