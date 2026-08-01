package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Jira opens a tracking issue for a scan by calling the Jira Cloud REST API
// (POST /rest/api/2/issue). It creates a single summary issue describing the
// run, gated by MinSeverity so a clean scan does not spam the backlog. Auth is
// HTTP basic with an account email and an API token, per Jira Cloud.
type Jira struct {
	BaseURL    string // e.g. https://acme.atlassian.net
	ProjectKey string // e.g. "SEC"
	Email      string
	Token      string
	IssueType  string // default "Task"
	// MinSeverity suppresses issue creation unless a finding at or above this
	// level exists. SeverityUnknown means "always create".
	MinSeverity engine.Severity
	Client      *http.Client
}

// NewJira builds a Jira connector with a default issue type and timeout.
func NewJira(baseURL, projectKey, email, token string) *Jira {
	return &Jira{
		BaseURL: strings.TrimRight(baseURL, "/"), ProjectKey: projectKey,
		Email: email, Token: token, IssueType: "Task",
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (j *Jira) Name() string { return "jira" }

func (j *Jira) Send(ctx context.Context, r *engine.Report) error {
	if j.MinSeverity != engine.SeverityUnknown && !r.FailsAt(j.MinSeverity) {
		return nil // below threshold: nothing worth filing
	}
	issueType := j.IssueType
	if issueType == "" {
		issueType = "Task"
	}
	// Jira's v2 create-issue payload. Description is plain text (v2 wiki markup).
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": j.ProjectKey},
			"issuetype":   map[string]string{"name": issueType},
			"summary":     j.summary(r),
			"description": j.description(r),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL+"/rest/api/2/issue", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(j.Email, j.Token)

	resp, err := j.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("jira create-issue returned %s", resp.Status)
	}
	return nil
}

func (j *Jira) summary(r *engine.Report) string {
	c := r.Counts()
	return fmt.Sprintf("[docker-security] %s: %d findings (crit=%d high=%d)",
		r.Target, len(r.Findings), c[engine.SeverityCritical], c[engine.SeverityHigh])
}

func (j *Jira) description(r *engine.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Automated scan of %q by docker-security.\n\n", r.Target)
	c := r.Counts()
	fmt.Fprintf(&b, "Severity: critical=%d high=%d medium=%d low=%d info=%d\n\nTop findings:\n",
		c[engine.SeverityCritical], c[engine.SeverityHigh], c[engine.SeverityMedium],
		c[engine.SeverityLow], c[engine.SeverityInfo])
	for i, f := range r.Findings {
		if i >= 20 {
			fmt.Fprintf(&b, "... and %d more\n", len(r.Findings)-20)
			break
		}
		fmt.Fprintf(&b, "- [%s] %s: %s\n", f.Severity, f.RuleID, f.Title)
	}
	return b.String()
}

func (j *Jira) client() *http.Client {
	if j.Client != nil {
		return j.Client
	}
	return http.DefaultClient
}
