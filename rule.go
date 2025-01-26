package sniproxy

import (
	"fmt"
	"regexp"
	"strings"
)

type DomainRule struct { //低效率, 但是无所谓
	suffixList  []string
	regexpList  []*regexp.Regexp
	keywordList []string
	fullMap     map[string]struct{}
}

func NewDomainRule() *DomainRule {
	r := &DomainRule{
		fullMap: make(map[string]struct{}),
	}
	return r
}

func (r *DomainRule) AddRules(rules ...string) error {
	for _, rule := range rules {
		if err := r.AddRule(rule); err != nil {
			return err
		}
	}
	return nil
}

func (r *DomainRule) AddRule(rule string) error {
	idx := strings.Index(rule, ":")
	if idx < 0 {
		return r.addSuffixRule(rule)
	}
	typ := rule[:idx]
	domain := rule[idx+1:]
	switch typ {
	case "full":
		return r.addFullRule(domain)
	case "regexp":
		return r.addRegexpRule(domain)
	case "keyword":
		return r.addKeywordRule(domain)
	default:
		return fmt.Errorf("unknown rule type:%s", typ)
	}
}

func (r *DomainRule) addSuffixRule(domain string) error {
	r.suffixList = append(r.suffixList, domain)
	return nil
}

func (r *DomainRule) addFullRule(domain string) error {
	r.fullMap[domain] = struct{}{}
	return nil
}

func (r *DomainRule) addRegexpRule(domain string) error {
	re, err := regexp.Compile(domain)
	if err != nil {
		return err
	}
	r.regexpList = append(r.regexpList, re)
	return nil
}

func (r *DomainRule) addKeywordRule(domain string) error {
	r.keywordList = append(r.keywordList, domain)
	return nil
}

func (r *DomainRule) Check(domain string) bool {
	if _, ok := r.fullMap[domain]; ok {
		return true
	}
	for _, suffix := range r.suffixList {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	for _, kw := range r.keywordList {
		if strings.Contains(domain, kw) {
			return true
		}
	}
	for _, re := range r.regexpList {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}
