package main

import (
	"fmt"
	nessusreport "github.com/Realize-Security/goNessus/internal/report/nessus"
	"github.com/Realize-Security/goNessus/internal/search"
	"github.com/Realize-Security/goNessus/pkg/models"
	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
)

type CLI struct {
	NessusFiles string   `name:"nessus" help:".nessus XML NessusReport" required:"" type:"path"`
	Patterns    []string `name:"pattern" help:"Search patterns in format 'expression::title::type::options'. Multiple patterns allowed." type:"strings"`
	PatternFile string   `name:"pattern-file" help:"YAML file containing patterns" type:"path"`
	CsvOnly     bool     `name:"csv-only" help:"Output .nessus direct to CSV."`
}

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

func (c *CLI) Validate(ctx *kong.Context) error {
	files := strings.Split(c.NessusFiles, ",")
	for _, file := range files {
		file = strings.TrimSpace(file) // Handle any spaces after commas
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", file)
		}
	}

	if c.PatternFile != "" {
		if _, err := os.Stat(c.PatternFile); os.IsNotExist(err) {
			return fmt.Errorf("pattern file %s does not exist", c.PatternFile)
		}
	}
	return nil
}

func loadPatternsFromYAML(filepath string) ([]*models.PatternDetails, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading pattern file: %v", err)
	}

	var config models.PatternConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing pattern file: %v", err)
	}

	patterns := make([]*models.PatternDetails, 0, len(config.Patterns))
	for _, entry := range config.Patterns {
		patterns = append(patterns, &entry.Pattern)
	}

	return patterns, nil
}

func main() {
	var cli CLI
	_ = kong.Parse(&cli,
		kong.Description(description()),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}),
	)

	pat := search.NewPatternRepository()
	patterns := make([]*models.PatternDetails, 0)

	// Load patterns from YAML file if specified
	if cli.PatternFile != "" {
		yamlPatterns, err := loadPatternsFromYAML(cli.PatternFile)
		if err != nil {
			log.Fatalf("Error loading patterns from YAML: %v", err)
		}
		log.Printf("Loaded %d patterns from YAML file", len(yamlPatterns))
		patterns = append(patterns, yamlPatterns...)
	}

	// Add command-line patterns
	for _, rawPattern := range cli.Patterns {
		pattern, err := pat.ParsePattern(rawPattern)
		if err != nil {
			log.Fatalf("Invalid pattern %q: %v", rawPattern, err)
		}
		patterns = append(patterns, pattern)
	}

	// Validate we have at least one pattern unless we're just doing CSV output
	if len(patterns) == 0 && !cli.CsvOnly {
		log.Fatal("No patterns specified. Use --pattern or --pattern-file to specify search patterns")
	}

	nessus := nessusreport.NewNessusRepository()

	inputFiles := strings.Split(cli.NessusFiles, ",")
	report, err := nessus.ParseMultipleNessusFiles(inputFiles...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error parsing nessus report:", err)
		os.Exit(1)
	}

	// Handle CSV-only output
	if cli.CsvOnly {
		if err := nessus.ToCSV(report); err != nil {
			fmt.Fprintln(os.Stderr, "error processing report:", err)
			os.Exit(1)
		}
		return
	}

	// Process report with patterns
	fr, err := nessus.FilterIssuesByPlugin(report, patterns, pat)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error processing report:", err)
		os.Exit(1)
	}
	for key, _ := range fr.Issues {
		fmt.Println(key)
	}
}

func description() string {
	return `
Process and filter Nessus reports.

Patterns can be specified in two ways:
1. Command line using --pattern flag
2. YAML file using --pattern-file flag

Command line pattern format: expression::title::type::options
- expression: The search pattern
- title: Display title (optional)
- type: simple, regex, or glob (optional)
- options: Comma-separated options (optional):
    - case: Enable case sensitivity
    - inverse: Invert the match
    - fields=field1+field2: Specify fields to search

YAML file format example:
  patterns:
    - pattern:
        expression: "ssl"
        title: "SSL Issues"
        type: "regex"
        case_sensitive: false
        inverse: false
        fields: ["plugin_output", "description"]

Examples:
  # Using command line pattern
  kong --nessus report.nessus --pattern "CVE-\\d+::CVE Findings::regex"

  # Using pattern file
  kong --nessus report.nessus --pattern-file patterns.yml

  # Using both
  kong --nessus report.nessus --pattern-file patterns.yml --pattern "SQL*::SQL Issues::glob"
`
}
