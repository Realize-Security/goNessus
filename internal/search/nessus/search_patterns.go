package search

import (
	"fmt"
	"github.com/Realize-Security/goNessus/pkg/models"
	"path"
	"regexp"
	"strings"
)

type PatternMatchingRepository interface {
	ParsePattern(raw string) (*models.PatternDetails, error)
	Matches(pattern *models.PatternDetails, text string) bool
}

type patternRepository struct{}

func NewPatternRepository() PatternMatchingRepository {
	return &patternRepository{}
}

// ParsePattern converts a raw user-defined pattern string into a PatternDetails struct
func (p *patternRepository) ParsePattern(raw string) (*models.PatternDetails, error) {
	// expression::title::type::options
	// Split on double colons to allow single colons in regex
	parts := strings.Split(raw, "::")

	pattern := &models.PatternDetails{
		Expression:    parts[0],
		Type:          string(models.SimpleMatch), // Default to simple matching
		CaseSensitive: false,                      // Default to case-insensitive
	}

	// Parse the different parts
	for i, part := range parts {
		switch i {
		case 0:
			continue
		case 1:
			pattern.Title = part
		case 2:
			switch strings.ToLower(part) {
			case "regex", "re":
				pattern.Type = string(models.RegexMatch)
			case "glob":
				pattern.Type = string(models.GlobMatch)
			case "simple":
				pattern.Type = string(models.SimpleMatch)
			default:
				return nil, fmt.Errorf("invalid pattern type: %s", part)
			}
		case 3: // Options
			for _, opt := range strings.Split(part, ",") {
				switch strings.ToLower(opt) {
				case "case":
					pattern.CaseSensitive = true
				case "inverse":
					pattern.Inverse = true
				default:
					if strings.HasPrefix(opt, "fields=") {
						pattern.Fields = strings.Split(strings.TrimPrefix(opt, "fields="), "+")
					}
				}
			}
		}
	}

	// If no title was provided, use the expression
	if pattern.Title == "" {
		pattern.Title = pattern.Expression
	}
	return pattern, nil
}

// Matches checks if the given text matches the pattern according to its rules
func (p *patternRepository) Matches(pattern *models.PatternDetails, text string) bool {
	var matches bool

	switch models.PatternType(pattern.Type) {
	case models.RegexMatch:
		flags := ""
		if !pattern.CaseSensitive {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + pattern.Expression)
		if err != nil {
			return false
		}
		matches = re.MatchString(text)

	case models.GlobMatch:
		if !pattern.CaseSensitive {
			text = strings.ToLower(text)
			pat := strings.ToLower(pattern.Expression)
			matches, _ = path.Match(pat, text)
		} else {
			matches, _ = path.Match(pattern.Expression, text)
		}

	default: // SimpleMatch
		if pattern.CaseSensitive {
			matches = strings.Contains(text, pattern.Expression)
		} else {
			matches = strings.Contains(
				strings.ToLower(text),
				strings.ToLower(pattern.Expression),
			)
		}
	}

	if pattern.Inverse {
		return !matches
	}
	return matches
}
