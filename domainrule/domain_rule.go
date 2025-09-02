package domainrule

import (
	"context"
	"fmt"
	"sniproxy/constant"
	"strings"
)

type domainRuleCheckItem struct {
	ck   IDomainRuleChecker
	data interface{}
}

type domainRuleImpl struct { //低效率, 但是无所谓
	checkerList []domainRuleCheckItem
}

type IDomainRule interface {
	Add(rule string, data interface{}) error
	Check(ctx context.Context, domain string) (interface{}, bool, error)
}

type DomainRuleCheckerCreatorFunc func(typ string, args string) (IDomainRuleChecker, error)

var mp = make(map[string]DomainRuleCheckerCreatorFunc, 16)

func Register(name string, fn DomainRuleCheckerCreatorFunc) {
	mp[name] = fn
}

func MakeRuleChecker(typ string, args string) (IDomainRuleChecker, error) {
	c, ok := mp[typ]
	if !ok {
		return nil, fmt.Errorf("type:%s not found", typ)
	}
	return c(typ, args)
}

func NewDomainRule() IDomainRule {
	r := &domainRuleImpl{
		checkerList: make([]domainRuleCheckItem, 0, 16),
	}
	return r
}

func (r *domainRuleImpl) Add(rule string, data interface{}) error {
	idx := strings.Index(rule, ":")
	var typ = constant.DomainTypeSuffix
	var domain = rule
	if idx > 0 {
		typ = rule[:idx]
		domain = rule[idx+1:]
	}
	if len(typ) == 0 || len(domain) == 0 {
		return fmt.Errorf("invalid rule type/domain, rule:%s", rule)
	}
	ck, err := MakeRuleChecker(typ, domain)
	if err != nil {
		return fmt.Errorf("make rule checker failed, rule:%s, err:%w", rule, err)
	}
	r.checkerList = append(r.checkerList, domainRuleCheckItem{
		ck:   ck,
		data: data,
	})
	return nil
}

func (r *domainRuleImpl) Check(ctx context.Context, domain string) (interface{}, bool, error) {
	for _, item := range r.checkerList {
		ok, err := item.ck.IsMatch(ctx, domain)
		if err != nil {
			return nil, false, err
		}
		if ok {
			return item.data, true, nil
		}
	}
	return nil, false, nil
}
