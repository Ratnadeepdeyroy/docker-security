package harden

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAppArmorContents(t *testing.T) {
	p := GenerateAppArmor(sampleObservation(), "web")
	got := p.Render()

	// Header + profile name (from "web").
	if !strings.Contains(got, "#include <tunables/global>") {
		t.Errorf("missing tunables include:\n%s", got)
	}
	if !strings.Contains(got, "profile web flags=(attach_disconnected,mediate_deleted) {") {
		t.Errorf("missing/renamed profile header:\n%s", got)
	}
	// The fixed deny block must always be present.
	for _, deny := range []string{
		"deny /var/run/docker.sock rwklx,",
		"deny @{PROC}/kcore rwklx,",
		"deny /etc/shadow rwklx,",
	} {
		if !strings.Contains(got, deny) {
			t.Errorf("missing deny rule %q", deny)
		}
	}
	// Observed capabilities appear lower-cased.
	for _, cap := range []string{"capability net_bind_service,", "capability setuid,", "capability setgid,"} {
		if !strings.Contains(got, cap) {
			t.Errorf("missing capability rule %q", cap)
		}
	}
	// Network was observed.
	if !strings.Contains(got, "network,") {
		t.Errorf("expected a network rule")
	}
	// Exec paths use inherit-exec (ix) so children stay confined.
	if !strings.Contains(got, "/app/server ix,") {
		t.Errorf("expected inherit-exec rule for /app/server:\n%s", got)
	}
	// Read + write globs pass through verbatim.
	if !strings.Contains(got, "/var/log/app/** w,") {
		t.Errorf("expected write rule for /var/log/app/**")
	}
	if !strings.Contains(got, "/etc/ssl/certs/** r,") {
		t.Errorf("expected read rule for /etc/ssl/certs/**")
	}
}

func TestAppArmorNameSanitised(t *testing.T) {
	p := GenerateAppArmor(Observation{}, "my app/v2:latest")
	if strings.ContainsAny(p.Name, " /:") {
		t.Errorf("profile name not sanitised: %q", p.Name)
	}
}

func TestAppArmorDeterministic(t *testing.T) {
	a := GenerateAppArmor(sampleObservation(), "web").Render()
	b := GenerateAppArmor(sampleObservation(), "web").Render()
	if a != b {
		t.Errorf("AppArmor generation is not deterministic")
	}
}

func TestAppArmorGolden(t *testing.T) {
	data := []byte(GenerateAppArmor(sampleObservation(), "web").Render())
	golden := filepath.Join("testdata", "web.apparmor.golden")
	if *update {
		if err := os.WriteFile(golden, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(want, data) {
		t.Errorf("apparmor golden mismatch; run `go test ./internal/harden/ -run Golden -update`")
	}
}
