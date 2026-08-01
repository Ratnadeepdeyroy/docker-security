package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/registry"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// Module is the supply-chain verification capability (CAPABILITY_SPEC domain 9).
// It supports image and registry targets and emits DS-RAT-SUP- findings.
type Module struct{}

// New returns a verify module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Verify image signatures, attestations, and signer policy (domain 9)"
}
func (m *Module) Domains() []string { return []string{"9"} }

func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetImage || t == engine.TargetRegistry
}

// Analyze resolves the verification inputs for the target (a trust config, a
// signature/attestation bundle, and the image digest), runs verification, and
// returns findings plus a verdict summary. Configuration travels via the
// target's Metadata so the module stays a pure function of its inputs:
//
//	verify.config   path to a JSON module Config (trust + requirements)
//	verify.trust    path to a raw sig.TrustConfig (shorthand for config.trust)
//	verify.bundle   path to a signature/attestation bundle JSON
//	image.digest    the manifest digest under test ("sha256:...")
//	verify.online   "true" to fetch the bundle from the registry via referrers
//
// With nothing configured it reports "not configured" (INFO) and verifies
// nothing — never a false pass.
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	md := t.Metadata
	if md == nil {
		md = map[string]string{}
	}

	cfg, haveCfg, err := loadConfig(md)
	if err != nil {
		return nil, err
	}
	res, err := cfg.build()
	if err != nil {
		return nil, err
	}

	imageDigest := resolveImageDigest(md, t)
	resource := t.Location
	if imageDigest != "" {
		resource = t.Location + "@" + imageDigest
	}

	bundle, err := loadBundle(ctx, md, t, imageDigest)
	if err != nil {
		return nil, err
	}

	// Nothing to work with: no config and no bundle. Report not-configured.
	if !haveCfg && bundle == nil {
		return []engine.Finding{finding(ruleNotConfigured, engine.SeverityInfo,
			"Supply-chain verification not configured",
			"No trust config or signature bundle was provided for this target; skipping verification.",
			resource, "Provide verify.trust/verify.config and a signature bundle, or use `dsecrat verify`.")}, nil
	}
	if bundle == nil {
		// Configured to verify, but no signatures at all were found.
		if imageDigest == "" {
			imageDigest = "sha256:" + strings.Repeat("0", 64) // placeholder never matches
		}
		empty, _ := sig.NewBundle(imageDigest)
		bundle = empty
	}

	v := verifyBundle(res, bundle, imageDigest, resource)
	v.add(verdictFinding(v, resource, imageDigest))
	return v.findings, nil
}

// verdictFinding summarizes the run as a single machine-readable verdict, the
// same signal a VSA carries: PASSED/FAILED plus the levels that were satisfied.
func verdictFinding(v *verdict, resource, digest string) engine.Finding {
	result := "PASSED"
	sev := engine.SeverityInfo
	if v.failed {
		result = "FAILED"
	}
	levels := sortedLevels(v.verifiedLevels)
	return findingWithMeta(ruleVerdict, sev,
		"Supply-chain verification verdict: "+result,
		fmt.Sprintf("Verified levels: %s.", strings.Join(levels, ", ")),
		resource, "", map[string]string{
			"verdict":         result,
			"verified_levels": strings.Join(levels, ","),
			"digest":          digest,
		})
}

// --- Input resolution -------------------------------------------------------

// loadConfig reads the module Config from metadata. verify.config takes a full
// Config JSON; verify.trust is shorthand for just the trust portion.
func loadConfig(md map[string]string) (Config, bool, error) {
	if p := md["verify.config"]; p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return Config{}, false, fmt.Errorf("read verify.config: %w", err)
		}
		cfg, err := ParseConfig(data)
		return cfg, true, err
	}
	if p := md["verify.trust"]; p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return Config{}, false, fmt.Errorf("read verify.trust: %w", err)
		}
		var raw sig.TrustConfig
		if err := json.Unmarshal(data, &raw); err != nil {
			return Config{}, false, fmt.Errorf("parse verify.trust: %w", err)
		}
		// Validate the keys parse before accepting the config.
		if _, _, err := raw.Build(); err != nil {
			return Config{}, false, err
		}
		return Config{Trust: raw}, true, nil
	}
	return Config{}, false, nil
}

// resolveImageDigest determines the manifest digest under test: an explicit
// metadata digest wins; otherwise, for an on-disk OCI layout, it is read from
// index.json. A digest we cannot determine is left empty, and verification then
// binds to the bundle's own subject (a weaker but still sound check).
func resolveImageDigest(md map[string]string, t *engine.Target) string {
	if d := md["image.digest"]; d != "" {
		if sig.ValidateDigest(d) == nil {
			return d
		}
	}
	if t.Type == engine.TargetImage && t.Location != "" {
		if info, err := os.Stat(t.Location); err == nil && info.IsDir() {
			if _, err := os.Stat(filepath.Join(t.Location, "index.json")); err == nil {
				if d, err := registry.ManifestDigestFromLayout(t.Location); err == nil {
					return d
				}
			}
		}
	}
	return ""
}

// loadBundle resolves the signature/attestation bundle: from a file, or (opt-in)
// from a live registry via referrers. Returns nil if no bundle is available.
func loadBundle(ctx context.Context, md map[string]string, t *engine.Target, imageDigest string) (*sig.Bundle, error) {
	if p := md["verify.bundle"]; p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read verify.bundle: %w", err)
		}
		return sig.ParseBundle(data)
	}
	if md["verify.online"] == "true" {
		return fetchBundleFromRegistry(ctx, t.Location, imageDigest, md["verify.registry_plain"] == "true")
	}
	return nil, nil
}

// fetchBundleFromRegistry pulls a verification bundle attached to an image via
// OCI referrers. It is opt-in (network) and degrades to a clear error offline.
func fetchBundleFromRegistry(ctx context.Context, ref, imageDigest string, plain bool) (*sig.Bundle, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	var opts []registry.Option
	if plain {
		opts = append(opts, registry.WithPlainHTTP())
	}
	client := registry.New(opts...)
	digest := imageDigest
	if digest == "" {
		digest, err = client.ResolveDigest(ctx, parsed)
		if err != nil {
			return nil, fmt.Errorf("resolve image digest: %w", err)
		}
	}
	idx, err := client.Referrers(ctx, parsed.Registry, parsed.Repository, digest, sig.BundleMediaType)
	if err != nil {
		return nil, fmt.Errorf("fetch referrers: %w", err)
	}
	for _, d := range idx.Manifests {
		rm, err := client.GetManifest(ctx, registry.Reference{Registry: parsed.Registry, Repository: parsed.Repository, Digest: d.Digest})
		if err != nil {
			continue
		}
		man, err := registry.ParseManifest(rm.Bytes)
		if err != nil || len(man.Layers) == 0 {
			continue
		}
		blob, err := client.GetBlob(ctx, parsed.Registry, parsed.Repository, man.Layers[0].Digest)
		if err != nil {
			continue
		}
		return sig.ParseBundle(blob)
	}
	return nil, nil
}
