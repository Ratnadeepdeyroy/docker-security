package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

// This file implements the daemon's output sinks. A Sink receives each detection
// record as it fires (streaming, SIEM-style), and a flush function prints the
// end-of-run summary. Two formats: human text and newline-delimited JSON (JSONL),
// the latter being what you would pipe into a log shipper or SIEM. In addition to
// the stdout stream, detections can fan out to a webhook, a local JSONL alert
// file, and/or the local syslog daemon.

// newSink returns a sink for the format (fanned out to any configured webhook,
// alert file, and/or syslog), plus a flush function that renders the run
// summary once the stream ends, plus a close function that must be called
// before the process exits to flush/close any file or syslog sinks.
func newSink(format, webhook, alertFile string, useSyslog bool) (rt.Sink, func(*rt.DaemonResult), func() error, error) {
	var stdout rt.Sink
	var flush func(*rt.DaemonResult)
	switch format {
	case "json":
		stdout = &jsonSink{enc: json.NewEncoder(os.Stdout)}
		flush = func(res *rt.DaemonResult) { summaryTo(os.Stderr, res) }
	default:
		stdout = &textSink{}
		flush = func(res *rt.DaemonResult) { summaryTo(os.Stdout, res) }
	}

	sinks := []rt.Sink{stdout}
	var closers []func() error

	if webhook != "" {
		sinks = append(sinks, &rt.WebhookSink{URL: webhook})
	}
	if alertFile != "" {
		fs, err := rt.NewFileSink(alertFile)
		if err != nil {
			return nil, nil, nil, err
		}
		sinks = append(sinks, fs)
		closers = append(closers, fs.Close)
	}
	if useSyslog {
		ss, err := rt.NewSyslogSink("dsecrat-runtime")
		if err != nil {
			return nil, nil, nil, err
		}
		sinks = append(sinks, ss)
		closers = append(closers, ss.Close)
	}

	closeSinks := func() error {
		var errs []error
		for _, c := range closers {
			if err := c(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}

	if len(sinks) == 1 {
		return sinks[0], flush, closeSinks, nil
	}
	return &rt.MultiSink{Sinks: sinks}, flush, closeSinks, nil
}

// --- text sink -----------------------------------------------------------

type textSink struct{}

// Emit prints one detection as a readable line, noting any response action and
// forensic evidence path.
func (s *textSink) Emit(rec rt.DetectionRecord) error {
	d := rec.Detection
	line := fmt.Sprintf("[%-8s] %s seq=%-3d %-10s %-24s %s",
		d.Severity, d.RuleID, d.Seq, d.Technique.ID, containerLabel(d.Container), d.Message)
	if rec.Action.Kind != rt.ActionAlert {
		line += fmt.Sprintf("  -> action=%s", rec.Action.Kind)
	}
	if rec.EvidencePath != "" {
		line += fmt.Sprintf("  [evidence:%s]", rec.EvidencePath)
	}
	fmt.Println(line)
	if rec.Incident != nil && len(rec.Incident.Playbook) > 0 {
		fmt.Printf("           incident %s — first step: %s\n", rec.Incident.ID, rec.Incident.Playbook[0].Action)
	}
	return nil
}

// --- json sink (JSONL) ---------------------------------------------------

type jsonSink struct{ enc *json.Encoder }

// Emit writes one record as a JSON line — the streaming, machine-consumable form.
func (s *jsonSink) Emit(rec rt.DetectionRecord) error {
	// Drop the bulky trigger event from the streamed record; forensics keeps it.
	rec.Detection.Trigger = nil
	return s.enc.Encode(rec)
}

// --- shared --------------------------------------------------------------

func containerLabel(c rt.ContainerInfo) string {
	if c.Name != "" {
		return c.Name
	}
	if c.ID != "" {
		return c.ID
	}
	return "-"
}

// summaryTo prints a one-line-per-severity run summary.
func summaryTo(w *os.File, res *rt.DaemonResult) {
	counts := map[string]int{}
	for _, rec := range res.Records {
		counts[rec.Detection.Severity.String()]++
	}
	fmt.Fprintf(w, "\nscanned %d events · %d detections (critical=%d high=%d medium=%d low=%d info=%d) · suppressed=%d\n",
		res.EventsScanned, len(res.Records),
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"], res.Suppressed)
	if len(res.EvidencePaths) > 0 {
		fmt.Fprintf(w, "forensic bundles: %d written\n", len(res.EvidencePaths))
	}
}
