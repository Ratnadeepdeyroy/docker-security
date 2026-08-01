// Package connector delivers a finished Report to an external destination
// (webhook, chat, CI artifact, …). A Connector is an outbound adapter: it takes
// the shared Report model and pushes it somewhere. Adding an integration means
// implementing this one interface.
package connector

import (
	"context"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Connector delivers a report to an external system.
type Connector interface {
	Name() string
	Send(ctx context.Context, r *engine.Report) error
}

// Dispatch sends the report to every connector, collecting (not aborting on)
// errors so one failing destination does not stop the others.
func Dispatch(ctx context.Context, r *engine.Report, conns ...Connector) []error {
	var errs []error
	for _, c := range conns {
		if c == nil {
			continue
		}
		if err := c.Send(ctx, r); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name(), err))
		}
	}
	return errs
}
