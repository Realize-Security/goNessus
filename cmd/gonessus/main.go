package main

import (
	"fmt"
	"github.com/Realize-Security/goNessus/internal/files"
	nessusreport "github.com/Realize-Security/goNessus/internal/report/nessus"
	"github.com/alecthomas/kong"
	"os"
)

type CLI struct {
	NessusFile string `name:"nessus" help:".nessus XML Report" required:"" type:"path"`
	Filter     string `name:"filter" help:"Filter issues by string. Not case sensitive" type:"string"`
	CsvOnly    bool   `name:"csv-only" help:"Output .nessus direct to CSV."`
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

	fb, err := files.ReadFileToBytes(cli.NessusFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encountered:", err)
		os.Exit(1)
	}

	report, err := nessusreport.ParseNessusReport(fb)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encountered:", err)
		os.Exit(1)
	}

	if cli.CsvOnly {
		if err := nessusreport.NessusXMLDirectToCSV(report); err != nil {
			fmt.Fprintln(os.Stderr, "error processing report:", err)
			os.Exit(1)
		}
		return
	}

}
