package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

// loadScenarioFile opens and parses a recorded telemetry scenario. Parsing (and
// its size guard) lives in internal/runtime; this is just the file plumbing.
func loadScenarioFile(path string) (*rt.Scenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open scenario %q: %w", path, err)
	}
	defer f.Close()
	sc, err := rt.LoadScenario(f)
	if err != nil {
		return nil, fmt.Errorf("load scenario %q: %w", path, err)
	}
	return sc, nil
}

// loadBaselineFile reads a learned baseline JSON for anomaly detection, bounding
// the read so a hostile file cannot exhaust memory.
func loadBaselineFile(path string) (*rt.Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline %q: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", path, err)
	}
	var b rt.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %q: %w", path, err)
	}
	return &b, nil
}
