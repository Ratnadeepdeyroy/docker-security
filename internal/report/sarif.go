package report

import (
	"encoding/json"
	"io"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// SARIF renders findings as a minimal SARIF 2.1.0 document, consumable by
// GitHub code scanning and other SARIF viewers.
type SARIF struct{}

func (SARIF) Format(w io.Writer, r *engine.Report) error {
	driver := sarifDriver{
		Name:           "docker-security",
		InformationURI: "https://example.invalid/docker-security",
		Rules:          []sarifRule{},
	}
	seenRule := map[string]bool{}
	results := []sarifResult{}

	for _, f := range r.Findings {
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			driver.Rules = append(driver.Rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: sarifText{Text: f.Title},
				HelpURI:          firstRef(f.References),
			})
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title},
		}
		if len(f.Metadata) > 0 {
			res.Properties = f.Metadata
		}
		uri := f.Resource
		var line int
		if f.Location != nil {
			if f.Location.Path != "" {
				uri = f.Location.Path
			}
			line = f.Location.StartLine
		}
		if uri != "" {
			loc := sarifLocation{}
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			if line > 0 {
				loc.PhysicalLocation.Region.StartLine = line
			}
			res.Locations = []sarifLocation{loc}
		}
		results = append(results, res)
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: driver},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s engine.Severity) string {
	switch s {
	case engine.SeverityCritical, engine.SeverityHigh:
		return "error"
	case engine.SeverityMedium, engine.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

func firstRef(refs []string) string {
	for _, r := range refs {
		if len(r) > 4 && r[:4] == "http" {
			return r
		}
	}
	return ""
}

// --- SARIF 2.1.0 subset types ---

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription sarifText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine,omitempty"`
		} `json:"region"`
	} `json:"physicalLocation"`
}
