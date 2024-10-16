package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule represents a matching rule
type Rule struct {
	Text          string         `json:"text"`
	CaseSensitive bool           `json:"caseSensitive"`
	PartialMatch  bool           `json:"partialMatch"`
	Regex         *regexp.Regexp `json:"-"`
	RegexString   string         `json:"regex"`
}

// ColorRule represents a color formatting rule
type ColorRule struct {
	Pattern string         `json:"pattern"`
	Regex   *regexp.Regexp `json:"-"`
	Color   string         `json:"color"`
	Label   string         `json:"label"`
	RuleID  string         `json:"rule_id"`
}

// ParseRule parses a rule input string into a Rule struct
func ParseRule(input string) (Rule, error) {
	if strings.TrimSpace(input) == "" {
		return Rule{}, fmt.Errorf("Rule cannot be empty")
	}

	caseSensitive := false
	partialMatch := true
	var compiledRegex *regexp.Regexp
	var regexString string

	if strings.HasPrefix(input, "regex:") {
		pattern := strings.TrimPrefix(input, "regex:")
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return Rule{}, fmt.Errorf("Invalid regex pattern: %v", err)
		}
		compiledRegex = regex
		regexString = pattern
	} else {
		if strings.HasPrefix(input, "sensitive:") {
			caseSensitive = true
			input = strings.TrimPrefix(input, "sensitive:")
		}
		if strings.HasPrefix(input, "full:") {
			partialMatch = false
			input = strings.TrimPrefix(input, "full:")
		}
	}

	return Rule{
		Text:          input,
		CaseSensitive: caseSensitive,
		PartialMatch:  partialMatch,
		Regex:         compiledRegex,
		RegexString:   regexString,
	}, nil
}

// MatchesAnyRule checks if a line matches any of the provided rules
func MatchesAnyRule(line string, rules []Rule) bool {
	for _, rule := range rules {
		if rule.Regex != nil {
			if rule.Regex.MatchString(line) {
				return true
			}
		} else {
			if rule.CaseSensitive {
				if rule.PartialMatch && strings.Contains(line, rule.Text) {
					return true
				} else if !rule.PartialMatch && line == rule.Text {
					return true
				}
			} else {
				lineLower := strings.ToLower(line)
				ruleTextLower := strings.ToLower(rule.Text)
				if rule.PartialMatch && strings.Contains(lineLower, ruleTextLower) {
					return true
				} else if !rule.PartialMatch && lineLower == ruleTextLower {
					return true
				}
			}
		}
	}
	return false
}

// RulesToStrings converts a slice of rules to their string representations
func RulesToStrings(rules []Rule) []string {
	var result []string
	for _, r := range rules {
		if r.Regex != nil {
			result = append(result, fmt.Sprintf("regex:%s", r.RegexString))
		} else {
			result = append(result, fmt.Sprintf("Text: %s, CaseSensitive: %v, PartialMatch: %v", r.Text, r.CaseSensitive, r.PartialMatch))
		}
	}
	return result
}
