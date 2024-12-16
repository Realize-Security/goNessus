package report

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"github.com/Realize-Security/goNessus/pkg/models"
	"os"
	"strconv"
	"strings"
)

// NessusXMLDirectToCSV converts Nessus' XML format directly to CSV output.
func NessusXMLDirectToCSV(report *models.NessusReport) error {
	w := csv.NewWriter(os.Stdout)
	headers := []string{
		"Host",
		"Operating System",
		"Host IP",
		"Finding Name",
		"Severity",
		"Severity Text",
		"Port",
		"Protocol",
		"Service",
		"Plugin ID",
		"Plugin Family",
		"CVSS Version",
		"CVSS Score",
		"CVSS Vector",
		"CVE",
		"Description",
		"Solution",
	}
	if err := w.Write(headers); err != nil {
		return fmt.Errorf("error writing headers: %w", err)
	}

	for _, host := range report.Report.ReportHost {
		var os, ip string
		for _, tag := range host.HostProperties.Tags {
			switch tag.Name {
			case "operating-system":
				os = tag.Value
			case "host-ip":
				ip = tag.Value
			}
		}

		for _, item := range host.ReportItems {
			// Skip informational findings
			if item.Severity < 1 {
				continue
			}

			version, score, vector := item.GetCVSS()

			record := []string{
				host.Name,
				os,
				ip,
				item.PluginName,
				strconv.Itoa(item.Severity),
				item.GetSeverityText(),
				strconv.Itoa(item.Port),
				item.Protocol,
				item.ServiceName,
				item.PluginID,
				item.PluginFamily,
				version,
				fmt.Sprintf("%.1f", score),
				vector,
				item.CVE,
				strings.ReplaceAll(item.Description, "\n", " "), // Remove newlines from description
				strings.ReplaceAll(item.Solution, "\n", " "),    // Remove newlines from solution
			}

			if err := w.Write(record); err != nil {
				return fmt.Errorf("error writing record: %w", err)
			}
		}
	}
	w.Flush()

	if err := w.Error(); err != nil {
		return fmt.Errorf("error flushing writer: %w", err)
	}
	return nil
}

// ParseNessusReport takes []byte format of a .nessus file and serializes to NessusReport.
func ParseNessusReport(xmlData []byte) (*models.NessusReport, error) {
	var report models.NessusReport
	err := xml.Unmarshal(xmlData, &report)
	if err != nil {
		return nil, fmt.Errorf("error parsing Nessus report: %w", err)
	}
	return &report, nil
}
