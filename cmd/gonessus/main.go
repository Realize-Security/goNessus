package main

import (
	"fmt"
	"github.com/Realize-Security/goNessus/internal/files"
	nessusreport "github.com/Realize-Security/goNessus/internal/report/nessus"
	"github.com/Realize-Security/goNessus/internal/search"
	"github.com/Realize-Security/goNessus/pkg/models"
	"github.com/alecthomas/kong"
	"log"
	"os"
)

type CLI struct {
	NessusFile string   `name:"nessus" help:".nessus XML NessusReport" required:"" type:"path"`
	Patterns   []string `name:"pattern" help:"Search patterns in format 'expression::title::type::options'. Multiple patterns allowed." type:"strings"`
	CsvOnly    bool     `name:"csv-only" help:"Output .nessus direct to CSV."`
}

func (c *CLI) Validate(ctx *kong.Context) error {
	if _, err := os.Stat(c.NessusFile); os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", c.NessusFile)
	}
	return nil
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

	patterns := make([]*models.Pattern, 0)
	for _, rawPattern := range cli.Patterns {
		pattern, err := pat.ParsePattern(rawPattern)
		if err != nil {
			log.Fatalf("Invalid pattern %q: %v", rawPattern, err)
		}
		patterns = append(patterns, pattern)
	}

	fb, err := files.ReadFileToBytes(cli.NessusFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encountered:", err)
		os.Exit(1)
	}

	nessus := nessusreport.NewNessusRepository()

	report, err := nessus.Parse(fb)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encountered:", err)
		os.Exit(1)
	}

	if cli.CsvOnly {
		if err := nessus.ToCSV(report); err != nil {
			fmt.Fprintln(os.Stderr, "error processing report:", err)
			os.Exit(1)
		}
		return
	}

	nessus.IssuesByPluginName(report, patterns, pat)
}

func description() string {
	return `
Process and filter Nessus reports.

Pattern format: expression::title::type::options

- expression: The search pattern

- title: Display title (optional)

- type: simple, regex, or glob (optional)

- options: Comma-separated options (optional):
    - case: Enable case sensitivity. Disabled by default.
    - inverse: Invert the match
    - fields=field1+field2: Specify fields to search

Examples:
  # Simple regex with title
  gonessus --nessus report.nessus --pattern "CVE-\\d+::CVE Findings::regex"

  # Case-sensitive glob pattern with inverse matching
  gonessus --nessus report.nessus --pattern "SQL*::SQL Issues::glob::case,inverse"

  # Regular expression searching specific fields
  gonessus --nessus report.nessus --pattern "(?:High|Critical)::Critical Issues::regex::fields=severity+risk"

  # Multiple patterns
  gonessus --nessus report.nessus \\
      --pattern "CVE-\\d+::CVE Findings::regex" \\
      --pattern "SQL*::SQL Issues::glob" \\
      --pattern "XSS::Cross-Site Scripting"
`
}
