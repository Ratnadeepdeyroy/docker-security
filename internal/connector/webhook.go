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

// Webhook POSTs the full JSON report to an arbitrary URL.
type Webhook struct {
	URL    string
	Client *http.Client
}

// NewWebhook builds a Webhook connector with a sane default timeout.
func NewWebhook(url string) *Webhook {
	return &Webhook{URL: url, Client: &http.Client{Timeout: 10 * time.Second}}
}

func (h *Webhook) Name() string { return "webhook" }

func (h *Webhook) Send(ctx context.Context, r *engine.Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "docker-security")

	resp, err := h.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s returned %s", h.URL, resp.Status)
	}
	return nil
}

func (h *Webhook) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}
