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
	_ = kong.Parse(&cli)

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
