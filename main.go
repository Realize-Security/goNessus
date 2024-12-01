package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

func main() {

	var nessusFile = "Report.nessus"
	fb, err := readFile(nessusFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encountered: %v\n", err)
		os.Exit(1)
	}

	report, err := parseNessusReport(fb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encountered: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(report.Report.Name)

}

func readFile(filename string) ([]byte, error) {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error encountered opening %s: %v", filename, err.Error())
	}
	return fileData, nil
}

func parseNessusReport(xmlData []byte) (*NessusClientData_v2, error) {
	var report NessusClientData_v2
	err := xml.Unmarshal(xmlData, &report)
	if err != nil {
		return nil, fmt.Errorf("error parsing Nessus report: %w", err)
	}
	return &report, nil
}

type NessusClientData_v2 struct {
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

	CVE                 string  `xml:"cve,omitempty"`
	CVSS3BaseScore      float64 `xml:"cvss3_base_score,omitempty"`
	CVSS3Vector         string  `xml:"cvss3_vector,omitempty"`
	CVSSBaseScore       float64 `xml:"cvss_base_score,omitempty"`
	CVSSScoreSource     string  `xml:"cvss_score_source,omitempty"`
	CVSSVector          string  `xml:"cvss_vector,omitempty"`
	CWE                 string  `xml:"cwe,omitempty"`
	VulnPublicationDate string  `xml:"vuln_publication_date,omitempty"`
	Xref                string  `xml:"xref,omitempty"`
}
