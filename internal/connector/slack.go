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

// Slack posts a summary message to a Slack incoming-webhook URL.
type Slack struct {
	WebhookURL string
	Client     *http.Client
	// MaxFindings caps how many individual findings are listed (0 = summary only).
	MaxFindings int
}

// NewSlack builds a Slack connector.
func NewSlack(url string) *Slack {
	return &Slack{WebhookURL: url, Client: &http.Client{Timeout: 10 * time.Second}, MaxFindings: 10}
}

func (s *Slack) Name() string { return "slack" }

func (s *Slack) Send(ctx context.Context, r *engine.Report) error {
	body, err := json.Marshal(map[string]string{"text": s.message(r)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %s", resp.Status)
	}
	return nil
}

func (s *Slack) message(r *engine.Report) string {
	c := r.Counts()
	var b strings.Builder
	fmt.Fprintf(&b, "*docker-security* scan of `%s`: %d findings — critical=%d high=%d medium=%d low=%d",
		r.Target, len(r.Findings),
		c[engine.SeverityCritical], c[engine.SeverityHigh], c[engine.SeverityMedium], c[engine.SeverityLow])
	for i, f := range r.Findings {
		if i >= s.MaxFindings {
			fmt.Fprintf(&b, "\n… and %d more", len(r.Findings)-s.MaxFindings)
			break
		}
		loc := f.Resource
		if f.Location != nil && f.Location.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
		}
		fmt.Fprintf(&b, "\n• [%s] %s — %s (%s)", f.Severity, f.RuleID, f.Title, loc)
	}
	return b.String()
}

func (s *Slack) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return http.DefaultClient
}
