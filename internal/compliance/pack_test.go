package compliance

import "testing"

func TestEmbeddedPacksLoad(t *testing.T) {
	cat, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatalf("LoadEmbeddedPacks: %v", err)
	}
	fws := cat.Frameworks()
	if len(fws) == 0 {
		t.Fatal("no packs loaded")
	}
	// cis-docker and nist-ssdf ship with the binary.
	have := map[string]bool{}
	for _, f := range fws {
		have[f] = true
	}
	for _, want := range []string{"cis-docker", "nist-ssdf", "nist-800-190"} {
		if !have[want] {
			t.Errorf("embedded pack %q missing (got %v)", want, fws)
		}
	}
	// Every control must declare an assessment method and, if automated, a check.
	for _, fw := range fws {
		for _, c := range cat.Controls(fw) {
			if c.ID == "" || c.Assessment == "" {
				t.Errorf("%s control %+v missing id/assessment", fw, c)
			}
			if c.Assessment == "automated" && c.Check == "" {
				t.Errorf("%s/%s is automated but has no check", fw, c.ID)
			}
		}
	}
}

func TestCrosswalkResolvesMappings(t *testing.T) {
	cat, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatal(err)
	}
	// CIS Docker 4.1 (non-root) must crosswalk to NIST 800-53 and PCI.
	edges := cat.MappedFrameworks("cis-docker", "4.1")
	if len(edges) == 0 {
		t.Fatal("4.1 has no crosswalk edges")
	}
	byFw := map[string][]string{}
	for _, e := range edges {
		byFw[e.Framework] = append(byFw[e.Framework], e.ID)
	}
	if len(byFw["nist-800-53-r5"]) == 0 || len(byFw["pci-dss-4.0.1"]) == 0 {
		t.Errorf("4.1 crosswalk missing NIST/PCI: %v", byFw)
	}
}

// TestNIST190PackMapsToolFindings confirms the NIST 800-190 pack ties the
// guide's core control sections to the tool's own automated checks and
// crosswalks each to the compliance frameworks auditors ask for — so one scan
// feeds NIST, PCI, and SOC 2 evidence.
func TestNIST190PackMapsToolFindings(t *testing.T) {
	cat, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatal(err)
	}
	controls := cat.Controls("nist-800-190")
	if len(controls) < 10 {
		t.Fatalf("nist-800-190 pack has only %d controls; expected the full section set", len(controls))
	}

	// Every automated control must reference a real DS-* check and crosswalk out.
	sawPCI, sawSOC2 := false, false
	for _, c := range controls {
		if c.Assessment == "automated" && c.Check == "" {
			t.Errorf("nist-800-190/%s automated but has no check", c.ID)
		}
		for fw := range c.MapsTo {
			if fw == "pci-dss-4.0.1" {
				sawPCI = true
			}
			if fw == "soc2-2017" {
				sawSOC2 = true
			}
		}
	}
	if !sawPCI || !sawSOC2 {
		t.Errorf("nist-800-190 pack should crosswalk to PCI and SOC2 (pci=%v soc2=%v)", sawPCI, sawSOC2)
	}

	// The image-vulnerability control must map to the vuln module's finding.
	var vulnCtl *PackControl
	for i := range controls {
		if controls[i].ID == "4.1.1" {
			vulnCtl = &controls[i]
		}
	}
	if vulnCtl == nil || vulnCtl.Module != "vuln" {
		t.Fatalf("nist-800-190 §4.1.1 should map to the vuln module, got %+v", vulnCtl)
	}
}
