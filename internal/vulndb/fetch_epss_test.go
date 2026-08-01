package vulndb

import (
	"os"
	"strings"
	"testing"
)

func TestParseEPSSCSV(t *testing.T) {
	f, err := os.Open("testdata/epss/sample.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := ParseEPSSCSV(f)
	if err != nil {
		t.Fatalf("ParseEPSSCSV: %v", err)
	}
	if len(m) != 3 {
		t.Fatalf("got %d scores, want 3: %v", len(m), m)
	}
	if got := m["CVE-2021-44228"]; got != 0.94445 {
		t.Errorf("Log4Shell EPSS = %v, want 0.94445", got)
	}
	if got := m["CVE-2024-3094"]; got != 0.00091 {
		t.Errorf("XZ EPSS = %v, want 0.00091", got)
	}
	// the comment line and the "cve,epss,percentile" header must not appear
	if _, ok := m["CVE"]; ok {
		t.Error("header row leaked into scores")
	}
	if _, ok := m["#MODEL_VERSION:V2025.03.14"]; ok {
		t.Error("comment line leaked into scores")
	}
}

func TestParseEPSSCSVSkipsMalformed(t *testing.T) {
	in := "#comment\ncve,epss,percentile\nCVE-1,notafloat,0.5\nCVE-2,0.42,0.9\nnot-a-cve,0.1,0.1\n"
	m, err := ParseEPSSCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m["CVE-2"] != 0.42 {
		t.Fatalf("expected only CVE-2=0.42, got %v", m)
	}
}
