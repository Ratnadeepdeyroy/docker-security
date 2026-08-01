package dockerfile

import (
	"context"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// analyze is a test helper that runs the module over inline Dockerfile content.
func analyze(t *testing.T, content string) []engine.Finding {
	t.Helper()
	m := New()
	fs, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetDockerfile,
		Location: "Dockerfile",
		Content:  []byte(content),
	})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	return fs
}

func ruleIDs(fs []engine.Finding) map[string]engine.Finding {
	m := map[string]engine.Finding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

func TestParseHandlesContinuationsAndComments(t *testing.T) {
	df := Parse("# comment\nFROM alpine:3.19\nRUN apt-get update \\\n  && apt-get install -y curl\n")
	if len(df.Instructions) != 2 {
		t.Fatalf("expected 2 instructions, got %d: %+v", len(df.Instructions), df.Instructions)
	}
	if df.Instructions[0].Cmd != "FROM" {
		t.Errorf("first instruction cmd = %q, want FROM", df.Instructions[0].Cmd)
	}
	run := df.Instructions[1]
	if run.Cmd != "RUN" {
		t.Errorf("second instruction cmd = %q, want RUN", run.Cmd)
	}
	if !strings.Contains(run.Args, "apt-get update") || !strings.Contains(run.Args, "install -y curl") {
		t.Errorf("continuation not joined: %q", run.Args)
	}
	if run.StartLine != 3 || run.EndLine != 4 {
		t.Errorf("RUN line span = %d-%d, want 3-4", run.StartLine, run.EndLine)
	}
}

func TestBadDockerfileTriggersExpectedRules(t *testing.T) {
	bad := `FROM ubuntu:latest
ENV API_KEY=supersecret123
RUN apt-get update && apt-get install -y curl
RUN curl https://example.com/install.sh | bash
ADD https://example.com/app.tar.gz /app
RUN sudo make install
`
	got := ruleIDs(analyze(t, bad))
	for _, want := range []string{
		"DS-RAT-DF-001", // ubuntu:latest
		"DS-RAT-DF-002", // no USER -> root
		"DS-RAT-DF-003", // no HEALTHCHECK
		"DS-RAT-DF-004", // ADD remote url
		"DS-RAT-DF-005", // apt-get install no cleanup
		"DS-RAT-DF-006", // API_KEY secret
		"DS-RAT-DF-007", // curl | bash
		"DS-RAT-DF-008", // sudo
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected rule %s to fire, but it did not (got: %v)", want, keys(got))
		}
	}
	// The secret finding must be HIGH severity.
	if f := got["DS-RAT-DF-006"]; f.Severity != engine.SeverityHigh {
		t.Errorf("DS-RAT-DF-006 severity = %s, want HIGH", f.Severity)
	}
}

func TestGoodDockerfileIsQuiet(t *testing.T) {
	good := `FROM alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1 ad4d
COPY --chown=app:app . /app
RUN adduser -D app
USER app
HEALTHCHECK CMD wget -q -O- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/app/server"]
`
	fs := analyze(t, good)
	for _, f := range fs {
		// A digest-pinned, non-root, healthchecked image should raise nothing
		// above INFO.
		if f.Severity > engine.SeverityInfo {
			t.Errorf("unexpected %s finding on good Dockerfile: %s (%s)", f.Severity, f.RuleID, f.Title)
		}
	}
}

func TestMultiStageDoesNotFlagStageReference(t *testing.T) {
	multi := `FROM golang:1.22@sha256:abc AS build
WORKDIR /src
RUN go build -o /bin/app
FROM build
USER 1000
HEALTHCHECK CMD true
`
	got := ruleIDs(analyze(t, multi))
	// "FROM build" references a prior stage; it must not be flagged as untagged.
	if _, ok := got["DS-RAT-DF-001"]; ok {
		t.Errorf("DS-RAT-DF-001 fired on a stage reference, which should be ignored")
	}
}

func keys(m map[string]engine.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func requireRule(t *testing.T, fs []engine.Finding, id string) {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == id {
			return
		}
	}
	t.Fatalf("expected finding %s, got %+v", id, fs)
}

func forbidRule(t *testing.T, fs []engine.Finding, id string) {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == id {
			t.Fatalf("unexpected finding %s: %+v", id, f)
		}
	}
}

func TestRuleUnpinnedPackages(t *testing.T) {
	src := "FROM debian:12\nRUN apt-get update && apt-get install -y curl\n"
	requireRule(t, analyze(t, src), "DS-RAT-DF-011")

	pinned := "FROM debian:12\nRUN apt-get install -y curl=8.5.0-2\n"
	forbidRule(t, analyze(t, pinned), "DS-RAT-DF-011")

	apk := "FROM alpine:3.21\nRUN apk add curl\n"
	requireRule(t, analyze(t, apk), "DS-RAT-DF-011")

	pip := "FROM python:3.12\nRUN pip install flask\n"
	requireRule(t, analyze(t, pip), "DS-RAT-DF-011")
}

func TestRuleUnpinnedPackagesEdgeCases(t *testing.T) {
	// apk with a pin must not fire.
	apkPinned := "FROM alpine:3.21\nRUN apk add curl=8.9.1-r0\n"
	forbidRule(t, analyze(t, apkPinned), "DS-RAT-DF-011")

	// pip with a == pin must not fire.
	pipPinned := "FROM python:3.12\nRUN pip install flask==3.0.0\n"
	forbidRule(t, analyze(t, pipPinned), "DS-RAT-DF-011")

	// pip3 variant.
	pip3 := "FROM python:3.12\nRUN pip3 install flask\n"
	requireRule(t, analyze(t, pip3), "DS-RAT-DF-011")

	// Multi-package install where only some packages are pinned must still fire.
	partial := "FROM debian:12\nRUN apt-get install -y curl=8.5.0-2 wget\n"
	requireRule(t, analyze(t, partial), "DS-RAT-DF-011")

	// Multi-package install where all packages are pinned must not fire.
	allPinned := "FROM debian:12\nRUN apt-get install -y curl=8.5.0-2 wget=1.21.3-1\n"
	forbidRule(t, analyze(t, allPinned), "DS-RAT-DF-011")

	// "apt install" (without -get) is also recognized.
	aptShort := "FROM debian:12\nRUN apt install -y curl\n"
	requireRule(t, analyze(t, aptShort), "DS-RAT-DF-011")
}

// TestRuleUnpinnedPackagesAptOptionBeforeInstall is a regression test for a
// review finding: an apt option token with uppercase letters/':'/'='/quotes
// (e.g. "-o Dpkg::Options::=\"--force-confdef\"") before "install" broke the
// aptInstallRe prefix scan entirely, making the whole invocation invisible to
// both DS-RAT-DF-011 and DS-RAT-DF-012.
func TestRuleUnpinnedPackagesAptOptionBeforeInstall(t *testing.T) {
	src := `FROM debian:12
RUN apt-get -o Dpkg::Options::="--force-confdef" install -y curl
`
	requireRule(t, analyze(t, src), "DS-RAT-DF-011")

	pinned := `FROM debian:12
RUN apt-get -o Dpkg::Options::="--force-confdef" install -y curl=8.5.0-2
`
	forbidRule(t, analyze(t, pinned), "DS-RAT-DF-011")
}

// TestRuleApkVirtualNotFlagged is a regression test for a review finding:
// apk's "--virtual <name>" idiom for a disposable build-dependency group
// (e.g. ".build-deps") was collected as if it were a real package, falsely
// flagging DS-RAT-DF-011 even when every real package was pinned.
func TestRuleApkVirtualNotFlagged(t *testing.T) {
	src := "FROM alpine:3.21\nRUN apk add --virtual .build-deps curl=8.5.0-r0\n"
	forbidRule(t, analyze(t, src), "DS-RAT-DF-011")
}

// TestRuleUnpinnedPackagesMultipleInstallsPerRun is a regression test for a
// review finding: a RUN chaining two installs must have EVERY invocation
// inspected, not just the first regex match.
func TestRuleUnpinnedPackagesMultipleInstallsPerRun(t *testing.T) {
	src := "FROM debian:12\n" +
		"RUN apt-get update && apt-get install -y curl=8.5.0-2 && apt-get install -y wget\n"
	requireRule(t, analyze(t, src), "DS-RAT-DF-011")

	allPinned := "FROM debian:12\n" +
		"RUN apt-get update && apt-get install -y curl=8.5.0-2 && apt-get install -y wget=1.21.3-1\n"
	forbidRule(t, analyze(t, allPinned), "DS-RAT-DF-011")
}

// TestRulePackagesOfPipIdioms is a regression test for a review finding:
// packagesOf mistook the value of pip's value-consuming flags (-r/-e/-c/-t
// and their long forms) for a package name, false-flagging the most common
// pip idioms as unpinned.
func TestRulePackagesOfPipIdioms(t *testing.T) {
	requirementsFile := "FROM python:3.12\nRUN pip install -r requirements.txt\n"
	forbidRule(t, analyze(t, requirementsFile), "DS-RAT-DF-011")

	editableCurrentDir := "FROM python:3.12\nRUN pip install -e .\n"
	forbidRule(t, analyze(t, editableCurrentDir), "DS-RAT-DF-011")

	longRequirementFlag := "FROM python:3.12\nRUN pip install --requirement reqs.txt\n"
	forbidRule(t, analyze(t, longRequirementFlag), "DS-RAT-DF-011")

	// A plain, unpinned package install must still fire.
	plainPackage := "FROM python:3.12\nRUN pip install flask\n"
	requireRule(t, analyze(t, plainPackage), "DS-RAT-DF-011")
}

func TestRuleNoInstallRecommends(t *testing.T) {
	src := "FROM debian:12\nRUN apt-get install -y curl=1.0\n"
	requireRule(t, analyze(t, src), "DS-RAT-DF-012")
	ok := "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl=1.0\n"
	forbidRule(t, analyze(t, ok), "DS-RAT-DF-012")
}

func TestRuleNoInstallRecommendsEdgeCases(t *testing.T) {
	// apk/pip installs are out of scope for DS-RAT-DF-012 (an apt-specific rule).
	apk := "FROM alpine:3.21\nRUN apk add curl=8.9.1-r0\n"
	forbidRule(t, analyze(t, apk), "DS-RAT-DF-012")

	pip := "FROM python:3.12\nRUN pip install flask==3.0.0\n"
	forbidRule(t, analyze(t, pip), "DS-RAT-DF-012")

	// --no-install-recommends present alongside cleanup.
	full := "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl=1.0 && rm -rf /var/lib/apt/lists/*\n"
	forbidRule(t, analyze(t, full), "DS-RAT-DF-012")
}

// TestRuleNoInstallRecommendsMultipleInstallsPerRun is a regression test for
// a review finding: each apt-get install invocation in a chained RUN must be
// evaluated independently. A whole-string Contains check was satisfied by
// the first install's flag, hiding a second install that lacked it.
func TestRuleNoInstallRecommendsMultipleInstallsPerRun(t *testing.T) {
	firstHasFlagSecondDoesnt := "FROM debian:12\n" +
		"RUN apt-get install -y --no-install-recommends curl=1.0 && apt-get install -y wget=1.0\n"
	requireRule(t, analyze(t, firstHasFlagSecondDoesnt), "DS-RAT-DF-012")

	bothHaveFlag := "FROM debian:12\n" +
		"RUN apt-get install -y --no-install-recommends curl=1.0 && apt-get install -y --no-install-recommends wget=1.0\n"
	forbidRule(t, analyze(t, bothHaveFlag), "DS-RAT-DF-012")
}

// TestRuleNoInstallRecommendsAptOptionBeforeInstall is a regression test:
// the same "-o Dpkg::Options::=..." preamble that blinded DS-RAT-DF-011 also
// blinded DS-RAT-DF-012, since both rely on aptInstallRe finding a match at all.
func TestRuleNoInstallRecommendsAptOptionBeforeInstall(t *testing.T) {
	src := `FROM debian:12
RUN apt-get -o Dpkg::Options::="--force-confdef" install -y curl=1.0
`
	requireRule(t, analyze(t, src), "DS-RAT-DF-012")

	ok := `FROM debian:12
RUN apt-get -o Dpkg::Options::="--force-confdef" install -y --no-install-recommends curl=1.0
`
	forbidRule(t, analyze(t, ok), "DS-RAT-DF-012")
}

// TestRuleUserRootBareUserDoesNotPanic is a regression test for a review
// finding: a bare "USER" instruction with no argument caused
// strings.Fields(ins.Args + " ")[0] to panic with an index-out-of-range,
// because strings.Fields(" ") returns an empty slice. A bare USER line must
// be treated like no USER was set at all, not crash the scan.
func TestRuleUserRootBareUserDoesNotPanic(t *testing.T) {
	src := "FROM alpine\nUSER\n"
	got := ruleIDs(analyze(t, src))
	if _, ok := got["DS-RAT-DF-002"]; !ok {
		t.Errorf("expected DS-RAT-DF-002 (root) to fire for a bare USER line, got %v", keys(got))
	}
}

func TestRulePipefail(t *testing.T) {
	src := "FROM debian:12\nRUN curl -s https://x.example/a.sh | sh\n"
	requireRule(t, analyze(t, src), "DS-RAT-DF-013")
	ok := "FROM debian:12\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN curl -s https://x.example/a.sh | sh\n"
	forbidRule(t, analyze(t, ok), "DS-RAT-DF-013")
	exec := "FROM debian:12\nRUN [\"/bin/app\", \"--flag\"]\n"
	forbidRule(t, analyze(t, exec), "DS-RAT-DF-013")
}

func TestRulePipefailEdgeCases(t *testing.T) {
	// exec-form RUN containing a literal "|" inside its args must not trigger
	// pipefail: it has no shell to evaluate a pipeline.
	execWithPipeChar := "FROM debian:12\nRUN [\"/bin/sh\", \"-c\", \"echo a | b\"]\n"
	forbidRule(t, analyze(t, execWithPipeChar), "DS-RAT-DF-013")

	// "||" is not a pipe and must not be flagged when there is no lone "|".
	orElse := "FROM debian:12\nRUN curl -s https://x.example/a.sh || true\n"
	forbidRule(t, analyze(t, orElse), "DS-RAT-DF-013")

	// "&&"/"||" combination with no real pipe must not be flagged.
	andOrElse := "FROM debian:12\nRUN make build || echo failed\n"
	forbidRule(t, analyze(t, andOrElse), "DS-RAT-DF-013")

	// An unguarded pipe followed by an unrelated "|| true" fallback is still a
	// genuine unguarded pipeline and must be flagged: the exit status of the
	// pipeline itself is never checked, only the shell's fallback to a
	// command unrelated to the pipe failure.
	pipeThenOrElse := "FROM debian:12\nRUN curl -s https://x.example/a.sh | sh || true\n"
	requireRule(t, analyze(t, pipeThenOrElse), "DS-RAT-DF-013")

	// SHELL sets pipefail for stage 1, but a new FROM starts stage 2 with the
	// default shell again, so the later piped RUN must still fire.
	resetByStage := "FROM debian:12 AS builder\n" +
		"SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\n" +
		"RUN curl -s https://x.example/a.sh | sh\n" +
		"FROM debian:12\n" +
		"RUN curl -s https://x.example/b.sh | sh\n"
	got := analyze(t, resetByStage)
	var lines []int
	for _, f := range got {
		if f.RuleID == "DS-RAT-DF-013" {
			lines = append(lines, f.Location.StartLine)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 DS-RAT-DF-013 finding (stage 1 covered by pipefail), got %d: %v", len(lines), lines)
	}
	if lines[0] != 5 {
		t.Errorf("expected the DS-RAT-DF-013 finding on line 5 (stage 2 RUN), got line %d", lines[0])
	}

	// A pipe together with "||" in the same RUN is still flagged: stripping the
	// "||" pairs out of the command leaves a lone "|", i.e. a real unguarded
	// pipeline (previously this was missed because ANY "||" suppressed the
	// check entirely).
	mixed := "FROM debian:12\nRUN curl -s https://x.example/a.sh | sh || true\n"
	requireRule(t, analyze(t, mixed), "DS-RAT-DF-013")

	// But a command that only uses "&&"/"||" for control flow, with no real
	// pipe character once "||" pairs are removed, must not be flagged.
	andOrOnly := "FROM debian:12\nRUN apt-get update && apt-get install -y curl || exit 1\n"
	forbidRule(t, analyze(t, andOrOnly), "DS-RAT-DF-013")
}

// TestRulePipefailQuotedPipeIsNotAPipeline is a regression test for a review
// finding: a literal '|' inside a quoted string (sed's alternate-delimiter
// idiom, or an echoed/printed string) is not a shell pipeline and must not
// be flagged, while a real unguarded pipe - with or without a trailing
// "|| true" fallback - must still fire.
func TestRulePipefailQuotedPipeIsNotAPipeline(t *testing.T) {
	sedAltDelim := "FROM debian:12\nRUN sed -i 's|foo|bar|g' x\n"
	forbidRule(t, analyze(t, sedAltDelim), "DS-RAT-DF-013")

	echoQuoted := `FROM debian:12
RUN echo "a|b"
`
	forbidRule(t, analyze(t, echoQuoted), "DS-RAT-DF-013")

	realPipe := "FROM debian:12\nRUN curl x | sh\n"
	requireRule(t, analyze(t, realPipe), "DS-RAT-DF-013")

	realPipeWithOrElse := "FROM debian:12\nRUN curl x | sh || true\n"
	requireRule(t, analyze(t, realPipeWithOrElse), "DS-RAT-DF-013")
}
