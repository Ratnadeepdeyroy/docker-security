package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Threat-intel IOC feed (DS-RAT-RT-014) --------------------------------

// IOCFeed is an offline threat-intel bundle: known-bad IPs, domains, and file
// hashes mapped to a short threat label. It is imported from a committed/airgap
// JSON file (no network fetch), keeping the sensor deterministic and dep-free.
type IOCFeed struct {
	Version string            `json:"version"`
	IPs     map[string]string `json:"ips"`
	Domains map[string]string `json:"domains"`
	Hashes  map[string]string `json:"hashes"`
}

// iocFeedSizeLimit bounds how much feed data we will parse from an untrusted
// file, mirroring LoadScenario's guard against a hostile/corrupt capture
// exhausting memory.
const iocFeedSizeLimit = 64 << 20 // 64 MiB

// LoadIOCFeed decodes an IOCFeed from a JSON file on disk, defending against
// oversized input and unknown fields exactly like LoadScenario does for
// recorded telemetry. Nil maps in the decoded feed are tolerated by the
// matching methods.
func LoadIOCFeed(path string) (*IOCFeed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ioc feed: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(f, iocFeedSizeLimit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read ioc feed: %w", err)
	}
	if len(data) > iocFeedSizeLimit {
		return nil, fmt.Errorf("ioc feed exceeds %d byte limit", iocFeedSizeLimit)
	}

	var feed IOCFeed
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&feed); err != nil {
		return nil, fmt.Errorf("decode ioc feed: %w", err)
	}
	return &feed, nil
}

// MatchNetwork checks a network event's remote IP, then its (lowercased)
// domain, against the feed. Nil maps are treated as empty.
func (f *IOCFeed) MatchNetwork(n *NetworkEvent) (label string, hit bool) {
	if f == nil || n == nil {
		return "", false
	}
	if n.RemoteIP != "" && f.IPs != nil {
		if lbl, ok := f.IPs[n.RemoteIP]; ok {
			return lbl, true
		}
	}
	if n.Domain != "" && f.Domains != nil {
		if lbl, ok := f.Domains[lowerASCII(n.Domain)]; ok {
			return lbl, true
		}
	}
	return "", false
}

// MatchFileHash checks a file hash against the feed's known-bad hash table.
func (f *IOCFeed) MatchFileHash(h string) (label string, hit bool) {
	if f == nil || h == "" || f.Hashes == nil {
		return "", false
	}
	lbl, ok := f.Hashes[h]
	return lbl, ok
}

// lowerASCII lowercases ASCII letters only — domains are ASCII, and this avoids
// pulling in unicode-aware casing for a simple lookup key.
func lowerASCII(s string) string {
	b := []byte(s)
	changed := false
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

// --- DS-RAT-RT-014 threat-intel IOC match ---------------------------------

type intelRule struct {
	ruleBase
	feed *IOCFeed
}

// newIntelRule builds the IOC-matching rule. It captures opts.IntelFeed and
// self-gates: with no feed configured, Evaluate always returns nil, so default
// detection stays deterministic and dependency-free (SHARED_CONTRACT §4).
func newIntelRule(opts Options) Rule {
	return &intelRule{
		ruleBase: ruleBase{
			id: "DS-RAT-RT-014",
			info: RuleInfo{
				Title:       "Threat-intel IOC match",
				Severity:    engine.SeverityHigh,
				Technique:   techAppLayerC2,
				Default:     true,
				Description: "A workload contacted a network endpoint matching a known-bad indicator (IP or domain) from an operator-supplied, offline threat-intel feed. This is a high-confidence signal: the endpoint has already been attributed to malicious infrastructure.",
				Remediation: "Isolate the workload and block the matched endpoint. Investigate the container for further compromise and rotate any credentials it could reach.",
			},
		},
		feed: opts.IntelFeed,
	}
}

func (r *intelRule) Evaluate(ev *Event, st *State) []Detection {
	if r.feed == nil {
		return nil
	}
	if ev.Kind != KindNetwork || ev.Network == nil {
		return nil
	}
	n := ev.Network
	label, hit := r.feed.MatchNetwork(n)
	if !hit {
		return nil
	}
	endpoint := endpointKey(n)
	return []Detection{r.fire(ev, "network endpoint "+endpoint+" matched threat-intel indicator: "+label,
		map[string]string{"endpoint": endpoint, "label": label, "vector": "network-ioc"})}
}
