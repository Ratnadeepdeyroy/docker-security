package vulndb

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func cveObjFromFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wrap struct {
		Vulnerabilities []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		t.Fatal(err)
	}
	if len(wrap.Vulnerabilities) == 0 {
		t.Fatal("no vulns in fixture")
	}
	return wrap.Vulnerabilities[0].CVE
}

func TestNormalizeNVD_XZ(t *testing.T) {
	advs, err := normalizeNVD(cveObjFromFixture(t, "testdata/nvd/cve-2024-3094.json"))
	if err != nil {
		t.Fatal(err)
	}
	// find the tukaani:xz advisory
	var xz *Advisory
	for i := range advs {
		if advs[i].Package == "tukaani:xz" {
			xz = &advs[i]
		}
	}
	if xz == nil {
		t.Fatalf("no tukaani:xz advisory; got %d advisories", len(advs))
	}
	if xz.ID != "CVE-2024-3094" {
		t.Errorf("ID=%q", xz.ID)
	}
	if xz.Ecosystem != Ecosystem("cpe") {
		t.Errorf("ecosystem=%q", xz.Ecosystem)
	}
	if xz.Severity != SevCritical {
		t.Errorf("severity=%q", xz.Severity)
	}
	if xz.CVSS == nil || xz.CVSS.Score != 10.0 {
		t.Errorf("cvss=%+v", xz.CVSS)
	}
	// exact versions 5.6.0 / 5.6.1 become Introduced==LastAffected ranges
	hasExact := false
	for _, r := range xz.Ranges {
		if r.Introduced == "5.6.0" && r.LastAffected == "5.6.0" {
			hasExact = true
		}
	}
	if !hasExact {
		t.Errorf("expected exact 5.6.0 range, got %+v", xz.Ranges)
	}
	if len(xz.CWEs) == 0 || xz.CWEs[0] != "CWE-506" {
		t.Errorf("cwes=%+v", xz.CWEs)
	}
	if xz.Source != "nvd" {
		t.Errorf("source=%q", xz.Source)
	}
}

func TestNormalizeNVD_Log4Shell(t *testing.T) {
	advs, err := normalizeNVD(cveObjFromFixture(t, "testdata/nvd/cve-2021-44228.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) == 0 {
		t.Fatal("expected advisories")
	}
	for _, a := range advs {
		if a.ID != "CVE-2021-44228" {
			t.Fatalf("wrong ID %q", a.ID)
		}
		if a.Severity != SevCritical {
			t.Errorf("sev=%q for %s", a.Severity, a.Package)
		}
	}
	// apache:log4j should be present with a version-end-excluding range
	found := false
	for _, a := range advs {
		if a.Package == "apache:log4j" {
			found = true
			hasFixed := false
			for _, r := range a.Ranges {
				if r.Fixed == "2.15.0" && r.Introduced == "2.13.0" {
					hasFixed = true
				}
			}
			if !hasFixed {
				t.Errorf("expected fixed range 2.13.0->2.15.0, got %+v", a.Ranges)
			}
		}
	}
	if !found {
		t.Errorf("expected apache:log4j among %d", len(advs))
	}
}

func TestNormalizeNVD_NoUsableCPE(t *testing.T) {
	doc := []byte(`{"id":"CVE-9999-0001","descriptions":[{"lang":"en","value":"no cpe here"}]}`)
	advs, err := normalizeNVD(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("expected no advisories, got %+v", advs)
	}
}

func TestNormalizeNVD_SkipsHardware(t *testing.T) {
	doc := []byte(`{
		"id":"CVE-9999-0002",
		"descriptions":[{"lang":"en","value":"hw only"}],
		"configurations":[{"nodes":[{"cpeMatch":[
			{"vulnerable":true,"criteria":"cpe:2.3:h:cisco:router9000:1.0:*:*:*:*:*:*:*"}
		]}]}]
	}`)
	advs, err := normalizeNVD(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("expected hardware CPE to be skipped, got %+v", advs)
	}
}

func TestNormalizeNVD_WildcardBecomesAllVersions(t *testing.T) {
	doc := []byte(`{
		"id":"CVE-9999-0003",
		"descriptions":[{"lang":"en","value":"wildcard everything"}],
		"configurations":[{"nodes":[{"cpeMatch":[
			{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}
		]}]}]
	}`)
	advs, err := normalizeNVD(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advs))
	}
	if len(advs[0].Ranges) != 1 || advs[0].Ranges[0].Introduced != "0" {
		t.Errorf("expected Introduced=0 approximation, got %+v", advs[0].Ranges)
	}
	if advs[0].Severity != SevUnknown || advs[0].CVSS != nil {
		t.Errorf("expected unknown severity/no cvss with no metrics, got %+v %+v", advs[0].Severity, advs[0].CVSS)
	}
}

func TestUpdateNVD_BuildsDB(t *testing.T) {
	f := staticFetcher{docs: [][]byte{cveObjFromFixture(t, "testdata/nvd/cve-2024-3094.json")}}
	db, err := UpdateNVD(context.Background(), f, "test-nvd", time.Unix(0, 0).UTC(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if db.Count() == 0 {
		t.Fatal("empty DB")
	}
	if db.Source != "test-nvd" {
		t.Errorf("source=%q", db.Source)
	}
}

type staticFetcher struct{ docs [][]byte }

func (s staticFetcher) Fetch(context.Context) ([][]byte, error) { return s.docs, nil }
