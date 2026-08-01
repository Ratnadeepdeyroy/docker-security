package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// SIEM ships each finding as a structured event to a generic HTTP collector
// (Splunk HEC, Elastic, a Logstash HTTP input, a custom SOC webhook). Events are
// newline-delimited JSON in an ECS-flavored shape, which most SIEMs ingest
// directly. It is intentionally vendor-neutral: point it at any endpoint that
// accepts a POST of NDJSON.
type SIEM struct {
	URL    string
	APIKey string // sent as "Authorization: <APIKey>" when non-empty
	Source string // event.provider label; default "docker-security"
	Client *http.Client
}

// NewSIEM builds a SIEM connector with a default timeout.
func NewSIEM(url string) *SIEM {
	return &SIEM{URL: url, Source: "docker-security", Client: &http.Client{Timeout: 15 * time.Second}}
}

func (s *SIEM) Name() string { return "siem" }

// event is one finding rendered as an ECS-flavored security event.
type event struct {
	Provider    string `json:"event.provider"`
	Kind        string `json:"event.kind"`     // "alert"
	Category    string `json:"event.category"` // "vulnerability" / "configuration"
	Target      string `json:"target"`
	TargetType  string `json:"target.type"`
	RuleID      string `json:"rule.id"`
	RuleName    string `json:"rule.name"`
	Module      string `json:"module"`
	Severity    string `json:"severity"`
	SeverityNum int    `json:"severity.num"`
	Resource    string `json:"resource,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func (s *SIEM) Send(ctx context.Context, r *engine.Report) error {
	source := s.Source
	if source == "" {
		source = "docker-security"
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // NDJSON: one JSON object per line
	for _, f := range r.Findings {
		ev := event{
			Provider: source, Kind: "alert", Category: categoryFor(f.Module),
			Target: r.Target, TargetType: string(r.TargetType),
			RuleID: f.RuleID, RuleName: f.Title, Module: f.Module,
			Severity: f.Severity.String(), SeverityNum: int(f.Severity),
			Resource: f.Resource, Remediation: f.Remediation,
		}
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.APIKey != "" {
		req.Header.Set("Authorization", s.APIKey)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem collector returned %s", resp.Status)
	}
	return nil
}

// categoryFor maps a module to a coarse ECS-style event category.
func categoryFor(module string) string {
	switch module {
	case "vuln":
		return "vulnerability"
	case "secrets":
		return "credential-exposure"
	default:
		return "configuration"
	}
}

func (s *SIEM) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return http.DefaultClient
}
