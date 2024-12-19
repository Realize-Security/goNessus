package models

type FinalReport struct {
	Issues map[string][]Issue `json:"issues"`
}

type Issue struct {
	Title         string         `json:"title"`
	AffectedHosts []AffectedHost `json:"affectedHosts"`
}

type AffectedHost struct {
	Hostname string            `json:"hostname"`
	Services []AffectedService `json:"services"`
}

type AffectedService struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
}
