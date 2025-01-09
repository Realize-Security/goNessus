package models

import "strings"

type NessusReport struct {
	Report Report `xml:"Report"`
}

type Report struct {
	Name       string       `xml:"name,attr"`
	ReportHost []ReportHost `xml:"ReportHost"`
}

type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItems    []ReportItem   `xml:"ReportItem"`
}

type HostProperties struct {
	Tags []Tag `xml:"tag"`
}

type Tag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type CVSSScore interface {
	GetVersion() string
	GetScore() float64
	GetVector() string
}

type CVSSv2 struct {
	BaseScore float64 `xml:"cvss_base_score,omitempty"`
	Vector    string  `xml:"cvss_vector,omitempty"`
	Source    string  `xml:"cvss_score_source,omitempty"`
}

// Implement CVSSScore interface for CVSSv2
func (c CVSSv2) GetVersion() string { return "2.0" }
func (c CVSSv2) GetScore() float64  { return c.BaseScore }
func (c CVSSv2) GetVector() string  { return c.Vector }

type CVSSv3 struct {
	BaseScore float64 `xml:"cvss3_base_score,omitempty"`
	Vector    string  `xml:"cvss3_vector,omitempty"`
}

// Implement CVSSScore interface for CVSSv3
func (c CVSSv3) GetVersion() string { return "3.0" }
func (c CVSSv3) GetScore() float64  { return c.BaseScore }
func (c CVSSv3) GetVector() string  { return c.Vector }

type ReportItem struct {
	Port         int    `xml:"port,attr"`
	ServiceName  string `xml:"svc_name,attr"`
	Protocol     string `xml:"protocol,attr"`
	Severity     int    `xml:"severity,attr"`
	PluginID     string `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	PluginFamily string `xml:"pluginFamily,attr"`

	Agent                  string `xml:"agent,omitempty"`
	AlwaysRun              int    `xml:"always_run,omitempty"`
	Description            string `xml:"description"`
	FileName               string `xml:"fname"`
	PluginModificationDate string `xml:"plugin_modification_date"`
	PluginPublicationDate  string `xml:"plugin_publication_date"`
	PluginType             string `xml:"plugin_type"`
	RiskFactor             string `xml:"risk_factor"`
	ScriptVersion          string `xml:"script_version"`
	Solution               string `xml:"solution"`
	Synopsis               string `xml:"synopsis"`
	ThoroughTests          bool   `xml:"thorough_tests,omitempty"`
	PluginOutput           string `xml:"plugin_output"`

	CVE                 string `xml:"cve,omitempty"`
	CWE                 string `xml:"cwe,omitempty"`
	VulnPublicationDate string `xml:"vuln_publication_date,omitempty"`
	Xref                string `xml:"xref,omitempty"`

	CVSSv2 `xml:",any"`
	CVSSv3 `xml:",any"`
}

func (r *ReportItem) GetSeverityText() string {
	switch r.Severity {
	case 4:
		return "Critical"
	case 3:
		return "High"
	case 2:
		return "Medium"
	case 1:
		return "Low"
	default:
		return "Info"
	}
}

func (r *ReportItem) HasCVE() bool {
	return r.CVE != ""
}

func (r *ReportItem) GetCVEs() []string {
	if r.CVE == "" {
		return nil
	}
	return strings.Split(r.CVE, ",")
}

func (r *ReportItem) GetCVSS() (version string, score float64, vector string) {
	if r.CVSSv3.BaseScore > 0 {
		return "3.0", r.CVSSv3.BaseScore, r.CVSSv3.Vector
	}

	if r.CVSSv2.BaseScore > 0 {
		return "2.0", r.CVSSv2.BaseScore, r.CVSSv2.Vector
	}
	return "", 0, ""
}

func (r *ReportItem) GetAllCVSS() []CVSSScore {
	var scores []CVSSScore

	if r.CVSSv2.BaseScore > 0 {
		scores = append(scores, r.CVSSv2)
	}
	if r.CVSSv3.BaseScore > 0 {
		scores = append(scores, r.CVSSv3)
	}
	return scores
}
