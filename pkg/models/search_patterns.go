package models

type PatternType string

const (
	SimpleMatch PatternType = "simple" // Case-insensitive substring match
	RegexMatch  PatternType = "regex"  // Regular expression match
	GlobMatch   PatternType = "glob"   // Glob pattern match
)

// Pattern represents a complex search pattern with various matching options
type Pattern struct {
	Expression    string      // The actual pattern to match
	Title         string      // Display title for the results
	Type          PatternType // Type of pattern matching to use
	CaseSensitive bool        // Whether to perform case-sensitive matching
	Inverse       bool        // Invert the match (match things that don't match the pattern)
	Fields        []string    // Specific fields to search in (empty means search all)
}
