package verify

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/attest"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/registry"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// --- dsecrat sign --------------------------------------------------------------

// SignCommand implements `dsecrat sign`: sign an image by digest and write a
// verification bundle. The master wires this as a top-level subcommand; the body
// lives here so cli.go stays a thin dispatcher.
func SignCommand(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	key := fs.String("key", "", "private key PEM (PKCS#8); omit with --new-key to generate one")
	newKey := fs.String("new-key", "", "generate a key of this algorithm: ed25519|ecdsa-p256")
	keyOut := fs.String("key-out", "", "write a generated private key here")
	pubOut := fs.String("pub-out", "", "write the signer public key PEM here")
	digest := fs.String("digest", "", "image manifest digest (sha256:...)")
	image := fs.String("image", "", "OCI image layout dir to derive the digest from")
	ref := fs.String("ref", "", "docker reference to record in the signature payload")
	tlog := fs.Bool("tlog", false, "record the signature in a local transparency log")
	logKey := fs.String("log-key", "", "transparency-log private key PEM (ed25519)")
	logKeyOut := fs.String("log-key-out", "", "write a generated transparency-log key here")
	bundleOut := fs.String("bundle-out", "-", "write the bundle here (default: stdout)")
	push := fs.Bool("push", false, "push the bundle to the registry via OCI referrers (network)")
	plain := fs.Bool("registry-plain", false, "use plain HTTP to the registry (local/test only)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	d, err := resolveDigest(*digest, *image)
	if err != nil {
		return fail("sign", err)
	}
	signer, err := loadOrGenerateKey(*key, *newKey, *keyOut, *pubOut)
	if err != nil {
		return fail("sign", err)
	}

	payload, err := sig.NewImagePayload(*ref, d, nil)
	if err != nil {
		return fail("sign", err)
	}
	env, err := sig.SignEnvelope(sig.SimpleSigningMediaType, payload, signer)
	if err != nil {
		return fail("sign", err)
	}

	var log *sig.TransLog
	if *tlog {
		lk, err := loadOrGenerateKey(*logKey, ternary(*logKey == "", "ed25519", ""), *logKeyOut, "")
		if err != nil {
			return fail("sign: transparency log key", err)
		}
		log = sig.NewTransLog(lk)
	}
	inc, err := maybeLog(log, env)
	if err != nil {
		return fail("sign", err)
	}

	bundle, err := loadOrNewBundle(*bundleOut, d)
	if err != nil {
		return fail("sign", err)
	}
	bundle.AddSignature(env, inc)

	if *push {
		if err := pushBundle(*ref, d, bundle, *plain); err != nil {
			return fail("sign: push", err)
		}
	}
	if err := writeBundle(bundle, *bundleOut); err != nil {
		return fail("sign", err)
	}
	fmt.Fprintf(os.Stderr, "sign: signed %s with key %s\n", d, shortID(signer.KeyID()))
	return 0
}

// --- dsecrat attest ------------------------------------------------------------

// AttestCommand implements `dsecrat attest`: build a signed in-toto attestation
// (SBOM, SLSA provenance, VEX, or an AI-agent-action) and add it to a bundle.
func AttestCommand(args []string) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	key := fs.String("key", "", "private key PEM (PKCS#8)")
	newKey := fs.String("new-key", "", "generate a key of this algorithm: ed25519|ecdsa-p256")
	keyOut := fs.String("key-out", "", "write a generated private key here")
	digest := fs.String("digest", "", "image manifest digest (sha256:...)")
	image := fs.String("image", "", "OCI image layout dir (for digest and/or SBOM generation)")
	ref := fs.String("ref", "", "artifact reference recorded as the subject name")
	predType := fs.String("type", "sbom", "predicate: sbom|provenance|vex|agent-action|<uri>")
	predFile := fs.String("predicate", "", "predicate JSON file (for provenance/vex/custom)")
	sbomFormat := fs.String("sbom-format", "cyclonedx", "SBOM format when --type sbom: cyclonedx|spdx")
	bundleOut := fs.String("bundle-out", "-", "write/append the bundle here (default: stdout)")
	// Agent-action flags (AI-age feature).
	agentID := fs.String("agent-id", "", "agent identifier (for --type agent-action)")
	agentModel := fs.String("agent-model", "", "agent model name")
	promptFile := fs.String("prompt-file", "", "file whose contents are the agent prompt (hashed, not stored)")
	actionType := fs.String("action-type", "build", "agent action type")
	actionTool := fs.String("action-tool", "dsecrat", "agent action tool")
	push := fs.Bool("push", false, "push the bundle to the registry via OCI referrers (network)")
	plain := fs.Bool("registry-plain", false, "use plain HTTP to the registry (local/test only)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	d, err := resolveDigest(*digest, *image)
	if err != nil {
		return fail("attest", err)
	}
	signer, err := loadOrGenerateKey(*key, *newKey, *keyOut, "")
	if err != nil {
		return fail("attest", err)
	}

	st, err := buildStatement(*predType, *ref, d, *predFile, *sbomFormat, *image, agentOpts{
		id: *agentID, model: *agentModel, promptFile: *promptFile, actionType: *actionType, actionTool: *actionTool,
	})
	if err != nil {
		return fail("attest", err)
	}
	env, err := attest.Sign(st, signer)
	if err != nil {
		return fail("attest", err)
	}

	bundle, err := loadOrNewBundle(*bundleOut, d)
	if err != nil {
		return fail("attest", err)
	}
	bundle.AddAttestation(env, nil)

	if *push {
		if err := pushBundle(*ref, d, bundle, *plain); err != nil {
			return fail("attest: push", err)
		}
	}
	if err := writeBundle(bundle, *bundleOut); err != nil {
		return fail("attest", err)
	}
	fmt.Fprintf(os.Stderr, "attest: added %s attestation for %s\n", predicateLabel(st.PredicateType), d)
	return 0
}

type agentOpts struct {
	id, model, promptFile, actionType, actionTool string
}

// buildStatement constructs the in-toto statement for the requested predicate.
func buildStatement(predType, ref, digest, predFile, sbomFormat, imagePath string, ao agentOpts) (*attest.Statement, error) {
	switch predType {
	case "sbom":
		data, err := loadSBOM(predFile, imagePath, ref, sbomFormat)
		if err != nil {
			return nil, err
		}
		return attest.NewSBOMStatement(ref, digest, sbomFormat, data)
	case "provenance":
		raw, err := os.ReadFile(predFile)
		if err != nil {
			return nil, fmt.Errorf("read provenance predicate: %w", err)
		}
		return attest.NewStatement(ref, digest, attest.PredicateSLSAProvenance, rawJSON(raw))
	case "vex":
		raw, err := os.ReadFile(predFile)
		if err != nil {
			return nil, fmt.Errorf("read vex predicate: %w", err)
		}
		return attest.NewStatement(ref, digest, attest.PredicateOpenVEX, rawJSON(raw))
	case "agent-action":
		return buildAgentActionStatement(ref, digest, ao)
	default:
		// Treat predType as a predicate-type URI with a supplied predicate file.
		raw, err := os.ReadFile(predFile)
		if err != nil {
			return nil, fmt.Errorf("read predicate: %w", err)
		}
		return attest.NewStatement(ref, digest, predType, rawJSON(raw))
	}
}

func buildAgentActionStatement(ref, digest string, ao agentOpts) (*attest.Statement, error) {
	if ao.promptFile == "" {
		return nil, fmt.Errorf("--prompt-file is required for --type agent-action")
	}
	prompt, err := os.ReadFile(ao.promptFile)
	if err != nil {
		return nil, fmt.Errorf("read prompt file: %w", err)
	}
	action := attest.AgentAction{
		Agent:     attest.Agent{ID: ao.id, Model: ao.model},
		Prompt:    attest.PromptRef{SHA256: attest.HashPrompt(prompt)},
		Action:    attest.ActionInfo{Type: ao.actionType, Tool: ao.actionTool, Target: ref},
		Timestamp: time.Now().UTC(),
	}
	return attest.NewAgentActionStatement(ref, digest, action)
}

// loadSBOM reads an SBOM from predFile, or generates one from an OCI image
// layout when no file is given. Generating reuses the Phase-1 SBOM library, so
// "sign the SBOM" and "produce the SBOM" share one code path.
func loadSBOM(predFile, imagePath, ref, format string) ([]byte, error) {
	if predFile != "" {
		return os.ReadFile(predFile)
	}
	if imagePath == "" {
		return nil, fmt.Errorf("provide --predicate (an SBOM file) or --image to generate one")
	}
	target := &engine.Target{Type: engine.TargetImage, Location: imagePath}
	doc, err := sbom.Generate(context.Background(), target)
	if err != nil {
		return nil, fmt.Errorf("generate SBOM: %w", err)
	}
	meta := sbom.DocMeta{
		Timestamp: time.Now().UTC(),
		Serial:    "urn:uuid:" + sbom.DeterministicUUID(ref+"|"+doc.Source.ImageDigest),
		ToolName:  "docker-security",
	}
	return sbom.Marshal(doc, sbom.Format(format), meta)
}

// --- dsecrat verify ------------------------------------------------------------

// VerifyCommand implements `dsecrat verify`: verify a bundle against a trust config
// and print the findings. Exit code is non-zero if the verdict fails.
func VerifyCommand(args []string) int {
	// `verify cosign ...` is the keyless (Fulcio) interop path; the default
	// `verify ...` remains the keyed DSSE-bundle path.
	if len(args) > 0 && args[0] == "cosign" {
		return verifyCosignCommand(args[1:])
	}
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "signature/attestation bundle JSON")
	trustPath := fs.String("trust", "", "trust config JSON (keys + policy)")
	configPath := fs.String("config", "", "full verify config JSON (trust + requirements)")
	digest := fs.String("digest", "", "image manifest digest (sha256:...)")
	image := fs.String("image", "", "OCI image layout dir to derive the digest from")
	require := fs.String("require", "", "comma-separated required predicate types (sbom,provenance,vex)")
	requireTlog := fs.Bool("require-tlog", false, "require a transparency-log proof for each signature")
	enableAgent := fs.Bool("enable-agent-actions", false, "surface AI-agent-action attestations (off by default)")
	vsaOut := fs.String("vsa-out", "", "write a signed Verification Summary Attestation here")
	vsaKey := fs.String("vsa-key", "", "key to sign the VSA (defaults to --trust is not usable; provide one)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadVerifyConfig(*configPath, *trustPath, *require, *requireTlog, *enableAgent)
	if err != nil {
		return fail("verify", err)
	}
	res, err := cfg.build()
	if err != nil {
		return fail("verify", err)
	}

	d, _ := resolveDigest(*digest, *image) // digest is optional for verify
	if *bundlePath == "" {
		return fail("verify", fmt.Errorf("--bundle is required"))
	}
	data, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fail("verify", err)
	}
	bundle, err := sig.ParseBundle(data)
	if err != nil {
		return fail("verify", err)
	}

	resource := d
	if resource == "" {
		resource = bundle.SubjectDigest
	}
	v := verifyBundle(res, bundle, d, resource)
	printFindings(v.findings)

	verdict := "PASSED"
	if v.failed {
		verdict = "FAILED"
	}
	fmt.Fprintf(os.Stderr, "verify: verdict %s (levels: %s)\n", verdict, strings.Join(sortedLevels(v.verifiedLevels), ","))

	if *vsaOut != "" {
		if err := emitVSA(*vsaOut, *vsaKey, res, bundle.SubjectDigest, v); err != nil {
			return fail("verify: vsa", err)
		}
	}
	if v.failed {
		return 1
	}
	return 0
}

// loadVerifyConfig builds the module Config from either a full --config file or
// a --trust file plus command-line requirement flags.
func loadVerifyConfig(configPath, trustPath, require string, requireTlog, enableAgent bool) (Config, error) {
	var cfg Config
	switch {
	case configPath != "":
		data, err := os.ReadFile(configPath)
		if err != nil {
			return cfg, err
		}
		cfg, err = ParseConfig(data)
		if err != nil {
			return cfg, err
		}
	case trustPath != "":
		data, err := os.ReadFile(trustPath)
		if err != nil {
			return cfg, err
		}
		var tc sig.TrustConfig
		if err := json.Unmarshal(data, &tc); err != nil {
			return cfg, fmt.Errorf("parse trust config: %w", err)
		}
		cfg.Trust = tc
	default:
		return cfg, fmt.Errorf("provide --trust or --config")
	}
	for _, r := range splitCSV(require) {
		cfg.RequireAttestations = append(cfg.RequireAttestations, requirePredicateURI(r))
	}
	cfg.RequireTransparencyLog = cfg.RequireTransparencyLog || requireTlog
	cfg.EnableAgentActions = cfg.EnableAgentActions || enableAgent
	return cfg, nil
}

// emitVSA writes a signed Verification Summary Attestation capturing the verdict.
func emitVSA(path, keyPath string, res *resolved, digest string, v *verdict) error {
	if keyPath == "" {
		return fmt.Errorf("--vsa-key is required to sign a VSA")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	signer, err := sig.LoadSignerPEM(data)
	if err != nil {
		return err
	}
	result := attest.VerdictPassed
	if v.failed {
		result = attest.VerdictFailed
	}
	vsa := attest.VSA{
		Verifier:           attest.VSAVerifier{ID: "github.com/Ratnadeepdeyroy/docker-security/dsecrat"},
		TimeVerified:       time.Now().UTC(),
		ResourceURI:        digest,
		VerificationResult: result,
		VerifiedLevels:     sortedLevels(v.verifiedLevels),
	}
	st, err := attest.NewStatement(digest, digest, attest.PredicateVSA, vsa)
	if err != nil {
		return err
	}
	env, err := attest.Sign(st, signer)
	if err != nil {
		return err
	}
	out, err := env.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// --- small utilities --------------------------------------------------------

func pushBundle(ref, digest string, bundle *sig.Bundle, plain bool) error {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		return err
	}
	var opts []registry.Option
	if plain {
		opts = append(opts, registry.WithPlainHTTP())
	}
	client := registry.New(opts...)
	data, err := bundle.Marshal()
	if err != nil {
		return err
	}
	_, err = client.PutReferrer(context.Background(), parsed.Registry, parsed.Repository, digest, sig.BundleMediaType, data, map[string]string{"kind": "bundle"})
	return err
}

func printFindings(findings []engine.Finding) {
	for _, f := range findings {
		fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", f.Severity, f.RuleID, f.Title)
		if f.Description != "" {
			fmt.Fprintf(os.Stdout, "        %s\n", f.Description)
		}
	}
}

func fail(op string, err error) int {
	fmt.Fprintf(os.Stderr, "%s: %v\n", op, err)
	return 1
}

func rawJSON(b []byte) any { return json.RawMessage(b) }

func requirePredicateURI(short string) string {
	switch short {
	case "sbom", "cyclonedx":
		return attest.PredicateCycloneDX
	case "spdx":
		return attest.PredicateSPDX
	case "provenance", "slsa":
		return attest.PredicateSLSAProvenance
	case "vex":
		return attest.PredicateOpenVEX
	default:
		return short
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
