package imageaudit

import "testing"

func TestParseConfigEmptyIsZeroValue(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("empty config should not error: %v", err)
	}
	if cfg.Config.User != "" || cfg.Config.Healthcheck != nil {
		t.Errorf("empty config should be zero-valued, got %+v", cfg.Config)
	}
}

func TestParseConfigMalformedErrors(t *testing.T) {
	if _, err := parseConfig([]byte("{not json")); err == nil {
		t.Error("malformed config JSON should return an error, not a panic or silent zero")
	}
}

func TestParseConfigReadsDockerV2Shape(t *testing.T) {
	raw := []byte(`{
      "architecture":"amd64","os":"linux",
      "config":{
        "User":"1000",
        "ExposedPorts":{"8080/tcp":{}},
        "Env":["FOO=bar"],
        "Labels":{"k":"v"},
        "Healthcheck":{"Test":["CMD","true"]}
      },
      "history":[{"created_by":"RUN x","empty_layer":true}]
    }`)
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Config.User != "1000" {
		t.Errorf("User = %q, want 1000", cfg.Config.User)
	}
	if _, ok := cfg.Config.ExposedPorts["8080/tcp"]; !ok {
		t.Errorf("ExposedPorts not parsed: %v", cfg.Config.ExposedPorts)
	}
	if !cfg.Config.hasHealthcheck() {
		t.Error("Healthcheck not parsed")
	}
	if len(cfg.History) != 1 || cfg.History[0].CreatedBy != "RUN x" {
		t.Errorf("history not parsed: %+v", cfg.History)
	}
}

func TestParseConfigBoundsHistory(t *testing.T) {
	// A hostile image could ship a huge history; we cap the scan.
	var b []byte
	b = append(b, []byte(`{"history":[`)...)
	for i := 0; i < maxHistoryEntries+50; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, []byte(`{"created_by":"RUN x","empty_layer":true}`)...)
	}
	b = append(b, []byte(`]}`)...)
	cfg, err := parseConfig(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.History) != maxHistoryEntries {
		t.Errorf("history length = %d, want capped at %d", len(cfg.History), maxHistoryEntries)
	}
}

func TestRunsAsRoot(t *testing.T) {
	cases := []struct {
		user     string
		root     bool
		explicit bool
	}{
		{"", true, false},
		{"root", true, true},
		{"0", true, true},
		{"0:0", true, true},
		{"1000", false, true},
		{"1000:1000", false, true},
		{"nonroot", false, true},
		{"  ", true, false}, // whitespace-only is effectively unset
	}
	for _, c := range cases {
		root, explicit := containerConfig{User: c.user}.runsAsRoot()
		if root != c.root || explicit != c.explicit {
			t.Errorf("runsAsRoot(%q) = (%v,%v), want (%v,%v)", c.user, root, explicit, c.root, c.explicit)
		}
	}
}

func TestHasHealthcheck(t *testing.T) {
	if (containerConfig{}).hasHealthcheck() {
		t.Error("nil healthcheck should be absent")
	}
	if (containerConfig{Healthcheck: &healthcheck{}}).hasHealthcheck() {
		t.Error("empty Test should be absent")
	}
	if (containerConfig{Healthcheck: &healthcheck{Test: []string{"NONE"}}}).hasHealthcheck() {
		t.Error("Test [NONE] should count as absent")
	}
	if !(containerConfig{Healthcheck: &healthcheck{Test: []string{"CMD", "true"}}}).hasHealthcheck() {
		t.Error("a real Test should be present")
	}
}
