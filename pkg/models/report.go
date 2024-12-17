package models

type FinalReport struct {
	Issues map[string]Issue `json:"issues"`
}

type Issue struct {
	Title         string   `json:"title"`
	AffectedHosts []string `json:"affectedHosts"`
}
