package sniproxy

import (
	"fmt"
	"regexp"
	"sniproxy/constant"
	"strings"
)

type domainRuleBasicItem struct {
	rule string
	data interface{}
}

type domainRuleRegexpItem struct {
	rule *regexp.Regexp
	data interface{}
}

type domainRuleImpl struct { //低效率, 但是无所谓
	suffixList  []domainRuleBasicItem
	regexpList  []domainRuleRegexpItem
	keywordList []domainRuleBasicItem
	fullMap     map[string]interface{}
}

type IDomainRule interface {
	Add(rule string, data interface{}) error
	Check(domain string) (interface{}, bool)
}

func NewDomainRule() IDomainRule {
	r := &domainRuleImpl{
		fullMap: make(map[string]interface{}),
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
	switch typ {
	case constant.DomainTypeFull:
		return r.addFullRule(domain, data)
	case constant.DomainTypeRegexp:
		return r.addRegexpRule(domain, data)
	case constant.DomainTypeKeyword:
		return r.addKeywordRule(domain, data)
	case constant.DomainTypeSuffix:
		return r.addSuffixRule(domain, data)
	default:
		return fmt.Errorf("unknown rule type:%s", typ)
	}
}

func (r *domainRuleImpl) addSuffixRule(domain string, data interface{}) error {
	r.suffixList = append(r.suffixList, domainRuleBasicItem{
		rule: domain,
		data: data,
	})
	return nil
}

func (r *domainRuleImpl) addFullRule(domain string, data interface{}) error {
	r.fullMap[domain] = data
	return nil
}

func (r *domainRuleImpl) addRegexpRule(domain string, data interface{}) error {
	re, err := regexp.Compile(domain)
	if err != nil {
		return err
	}
	r.regexpList = append(r.regexpList, domainRuleRegexpItem{
		rule: re,
		data: data,
	})
	return nil
}

func (r *domainRuleImpl) addKeywordRule(domain string, data interface{}) error {
	r.keywordList = append(r.keywordList, domainRuleBasicItem{
		rule: domain,
		data: data,
	})
	return nil
}

func (r *domainRuleImpl) Check(domain string) (interface{}, bool) {
	if v, ok := r.fullMap[domain]; ok {
		return v, true
	}
	for _, suffix := range r.suffixList {
		if strings.HasSuffix(domain, suffix.rule) {
			return suffix.data, true
		}
	}
	for _, kw := range r.keywordList {
		if strings.Contains(domain, kw.rule) {
			return kw.data, true
		}
	}
	for _, re := range r.regexpList {
		if re.rule.MatchString(domain) {
			return re.data, true
		}
	}
	return nil, false
}
