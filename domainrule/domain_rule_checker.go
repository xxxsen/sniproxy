package domainrule

import (
	"context"
)

type IDomainRuleChecker interface {
	IsMatch(ctx context.Context, domain string) (bool, error)
}
