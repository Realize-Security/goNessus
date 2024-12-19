package report

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"github.com/Realize-Security/goNessus/internal/files"
	"github.com/Realize-Security/goNessus/internal/search"
	"github.com/Realize-Security/goNessus/pkg/models"
	"os"
	"strconv"
	"strings"
)

type NessusReportRepository interface {
	Parse(data []byte) (*models.NessusReport, error)
	ParseMultipleNessusFiles(files []string) (*models.NessusReport, error)
	ToCSV(report *models.NessusReport) error
	IssuesByPluginName(report *models.NessusReport, patterns []*models.PatternDetails, matcher search.PatternMatchingRepository) (*models.FinalReport, error)
}

type nessusRepository struct{}

// NewNessusRepository creates a new instance of NessusReportRepository
func NewNessusRepository() NessusReportRepository {
	return &nessusRepository{}
}

// ToCSV converts Nessus' XML format directly to CSV output.
func (r *nessusRepository) ToCSV(report *models.NessusReport) error {
	w := csv.NewWriter(os.Stdout)
	headers := []string{
		"Host",
		"Operating System",
		"Host IP",
		"Finding HostName",
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
		var operatingsystem, ip string
		for _, tag := range host.HostProperties.Tags {
			switch tag.Name {
			case "operating-system":
				operatingsystem = tag.Value
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
				operatingsystem,
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

// Parse takes []byte format of a .nessus file and serializes to NessusReport.
func (r *nessusRepository) Parse(xmlData []byte) (*models.NessusReport, error) {
	var report models.NessusReport
	err := xml.Unmarshal(xmlData, &report)
	if err != nil {
		return nil, fmt.Errorf("error parsing Nessus report: %w", err)
	}
	return &report, nil
}

func (r *nessusRepository) ParseMultipleNessusFiles(filePaths []string) (*models.NessusReport, error) {
	mergedReport := &models.NessusReport{
		Report: models.Report{
			ReportHost: make([]models.ReportHost, 0),
		},
	}

	// Process each file
	for _, file := range filePaths {
		// Read file
		fb, err := files.ReadFileToBytes(file)
		if err != nil {
			return nil, fmt.Errorf("error reading file %s: %w", file, err)
		}

		// Parse individual report
		report, err := r.Parse(fb)
		if err != nil {
			return nil, fmt.Errorf("error parsing file %s: %w", file, err)
		}

		// Merge hosts from this report into the merged report
		mergedReport.Report.ReportHost = append(
			mergedReport.Report.ReportHost,
			report.Report.ReportHost...,
		)
	}

	return mergedReport, nil
}

// IssuesByPluginName groups issues by Nessus plugin name
func (r *nessusRepository) IssuesByPluginName(report *models.NessusReport, patterns []*models.PatternDetails, matcher search.PatternMatchingRepository) (*models.FinalReport, error) {
	// Pre-allocate maps
	hc := len(report.Report.ReportHost)
	totalIssues := totalPlugins(report.Report.ReportHost)

	// Data structures
	issueMap := make(map[string]*models.Issue, totalIssues)
	resultMap := make(map[string][]models.Issue, len(patterns))
	hostServiceMap := make(map[string]map[string]*models.AffectedHost, totalIssues)

	// Track which match group each plugin belongs to
	pluginMatchMap := make(map[string]string, totalIssues)

	// First pass: collect all issues and their hosts
	for _, host := range report.Report.ReportHost {
		for _, reportItem := range host.ReportItems {
			matchTitle, ok := matchesFilter(reportItem.PluginName, patterns, matcher)
			if !ok {
				continue
			}

			pluginMatchMap[reportItem.PluginName] = matchTitle

			issue, exists := issueMap[reportItem.PluginName]
			if !exists {
				issue = &models.Issue{
					Title:         reportItem.PluginName,
					AffectedHosts: make([]models.AffectedHost, 0, hc),
				}
				issueMap[reportItem.PluginName] = issue
				hostServiceMap[reportItem.PluginName] = make(map[string]*models.AffectedHost)
			}

			hostEntry, hostExists := hostServiceMap[reportItem.PluginName][host.Name]
			if !hostExists {
				newHost := models.AffectedHost{
					Hostname: host.Name,
					Services: []models.AffectedService{{
						Port:     reportItem.Port,
						Protocol: reportItem.Protocol,
						Service:  reportItem.ServiceName,
					}},
				}
				hostServiceMap[reportItem.PluginName][host.Name] = &newHost
				issue.AffectedHosts = append(issue.AffectedHosts, newHost)
			} else {
				hostEntry.Services = append(hostEntry.Services, models.AffectedService{
					Port:     reportItem.Port,
					Protocol: reportItem.Protocol,
					Service:  reportItem.ServiceName,
				})
			}
		}
	}

	// Second pass: build final result map after all hosts are collected
	for pluginName, issue := range issueMap {
		matchGroup := pluginMatchMap[pluginName]
		resultMap[matchGroup] = append(resultMap[matchGroup], *issue)
	}

	fr := &models.FinalReport{
		Issues: resultMap,
	}
	return fr, nil
}

func hostFound(tracked map[string]map[string]bool, hostname, plugin string) (hostFound bool) {
	if tracked[plugin][hostname] {
		return true
	}
	return
}

func totalPlugins(reportHost []models.ReportHost) int {
	tracked := make(map[string]bool)
	for _, host := range reportHost {
		for _, reportItem := range host.ReportItems {
			if !tracked[reportItem.PluginName] {
				tracked[reportItem.PluginName] = true
				continue
			}
		}
	}
	return len(tracked)
}

func matchesFilter(plugin string, patterns []*models.PatternDetails, matcher search.PatternMatchingRepository) (string, bool) {
	for _, pattern := range patterns {
		if matcher.Matches(pattern, plugin) {
			return pattern.Title, true
		}
	}
	return "", false
}
