package report

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"github.com/Realize-Security/goNessus/internal/search"
	"github.com/Realize-Security/goNessus/pkg/models"
	"os"
	"strconv"
	"strings"
)

type NessusReportRepository interface {
	Parse(data []byte) (*models.NessusReport, error)
	ToCSV(report *models.NessusReport) error
	IssuesByPluginName(report *models.NessusReport, patterns []*models.Pattern, matcher search.PatternMatchingRepository) *models.FinalReport
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

// IssuesByPluginName groups issues by Nessus plugin name
func (r *nessusRepository) IssuesByPluginName(report *models.NessusReport, patterns []*models.Pattern, matcher search.PatternMatchingRepository) *models.FinalReport {
	issueMap := make(map[string]*models.Issue)
	pluginToHost := make(map[string]map[string]bool)
	hc := len(report.Report.ReportHost)

	for _, host := range report.Report.ReportHost {
		for _, reportItem := range host.ReportItems {

			// Filter in target issues only
			matchTitle, res := matchesFilter(reportItem.PluginName, patterns, matcher)
			if !res {
				continue
			}
			issue, exists := issueMap[reportItem.PluginName]
			if !exists {
				issue = &models.Issue{
					FilterMatch:   matchTitle,
					Title:         reportItem.PluginName,
					AffectedHosts: make([]models.AffectedHost, 0, hc),
				}
				issueMap[reportItem.PluginName] = issue
				pluginToHost[reportItem.PluginName] = make(map[string]bool)
			}

			if !hostFound(pluginToHost, host.Name, reportItem.PluginName) {
				// Add new host with its first service
				issue.AffectedHosts = append(issue.AffectedHosts, models.AffectedHost{
					Hostname: host.Name,
					Services: []models.AffectedService{{
						Port:     reportItem.Port,
						Protocol: reportItem.Protocol,
						Service:  reportItem.ServiceName,
					}},
				})
				pluginToHost[reportItem.PluginName][host.Name] = true
			} else {
				// Find the correct host and append the service
				for i := range issue.AffectedHosts {
					if issue.AffectedHosts[i].Hostname == host.Name {
						issue.AffectedHosts[i].Services = append(issue.AffectedHosts[i].Services, models.AffectedService{
							Port:     reportItem.Port,
							Protocol: reportItem.Protocol,
							Service:  reportItem.ServiceName,
						})
						break
					}
				}
			}
		}
	}

	fr := &models.FinalReport{
		Issues: make([]models.Issue, 0, len(issueMap)),
	}
	for _, issue := range issueMap {
		fr.Issues = append(fr.Issues, *issue)
	}
	return fr
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

func matchesFilter(plugin string, patterns []*models.Pattern, matcher search.PatternMatchingRepository) (string, bool) {
	for _, pattern := range patterns {
		if matcher.Matches(pattern, plugin) {
			return pattern.Title, true
		}
	}
	return "", false
}
