package models

type PatternType string

const (
	SimpleMatch PatternType = "simple" // Case-insensitive substring match
	RegexMatch  PatternType = "regex"  // Regular expression match
	GlobMatch   PatternType = "glob"   // Glob pattern match
)

type PatternConfig struct {
	Patterns []PatternEntry `yaml:"patterns"`
}

type PatternEntry struct {
	Pattern PatternDetails `yaml:"pattern"`
}

type PatternDetails struct {
	Expression    string   `yaml:"expression"`
	Title         string   `yaml:"title"`
	Type          string   `yaml:"type"`
	CaseSensitive bool     `yaml:"case_sensitive,omitempty"`
	Inverse       bool     `yaml:"inverse,omitempty"`
	Fields        []string `yaml:"fields,omitempty"`
}
