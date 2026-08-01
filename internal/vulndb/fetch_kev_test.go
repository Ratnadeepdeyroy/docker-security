package vulndb

import (
	"os"
	"testing"
)

func TestParseKEV(t *testing.T) {
	data, err := os.ReadFile("testdata/kev/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := ParseKEV(data)
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d ids, want 2: %v", len(ids), ids)
	}
	// sorted, uppercased (the fixture has a lowercase cve-2024-3094)
	want := []string{"CVE-2021-44228", "CVE-2024-3094"}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("ids[%d]=%q, want %q", i, ids[i], want[i])
		}
	}
}

func TestParseKEVDedupsAndSkipsJunk(t *testing.T) {
	in := []byte(`{"vulnerabilities":[{"cveID":"CVE-1"},{"cveID":"CVE-1"},{"cveID":"notacve"},{"cveID":""}]}`)
	ids, err := ParseKEV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "CVE-1" {
		t.Fatalf("expected [CVE-1], got %v", ids)
	}
}
