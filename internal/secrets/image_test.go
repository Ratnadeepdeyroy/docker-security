package secrets

import (
	"context"
	"io/fs"
	"reflect"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// buildLayeredImage constructs an in-memory image that exercises the three
// image scan surfaces: a secret overwritten by a later layer, a secret deleted
// by a whiteout, a live secret, and secrets baked into the config env/history.
func buildLayeredImage() *oci.Image {
	ghToken := "github_token: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"
	return &oci.Image{
		Config: []byte(`{
			"config": {"Env": ["PATH=/usr/bin", "DJANGO_SECRET_KEY=k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi"]},
			"history": [
				{"created_by": "ADD file:abc in /"},
				{"created_by": "ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
			]
		}`),
		Layers: []*oci.Layer{
			{Index: 0, Digest: "sha256:layer0", Files: []*oci.File{
				{Path: "app/config.yaml", Data: []byte(ghToken)},                                       // overwritten later
				{Path: "app/main.py", Data: []byte("id = \"550e8400-e29b-41d4-a716-446655440000\"\n")}, // UUID, benign
			}},
			{Index: 1, Digest: "sha256:layer1", Files: []*oci.File{
				{Path: "srv/db.conf", Data: []byte("DATABASE_URL=postgres://admin:Tr0ub4dor3xyz@db:5432/app\n")}, // live
				{Path: "etc/secret.env", Data: []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")},               // deleted later
			}},
			{Index: 2, Digest: "sha256:layer2", Files: []*oci.File{
				{Path: "app/config.yaml", Data: []byte("github_token: redacted\n")}, // overwrites layer 0
				{Path: "etc/.wh.secret.env", Mode: fs.FileMode(0), Data: nil},       // whiteout deletes etc/secret.env
			}},
		},
	}
}

func TestScanImageLayerAware(t *testing.T) {
	s := New()
	ds := s.ScanImage(context.Background(), buildLayeredImage())
	got := codeSet(ds)

	// The GitHub token was overwritten in layer 2 but survives in layer 0.
	gh := got["DS-RAT-SEC-004"]
	if gh.Code == "" || !gh.Deleted || gh.LayerIndex != 0 {
		t.Errorf("github token: want deleted finding in layer 0, got %+v", gh)
	}
	// The AWS key was whiteout-deleted in layer 2 but survives in layer 1.
	aws := got["DS-RAT-SEC-001"]
	if aws.Code == "" || !aws.Deleted || aws.LayerIndex != 1 {
		t.Errorf("aws key: want deleted finding in layer 1, got %+v", aws)
	}
	// The DB URI ships in the effective filesystem: live, not deleted.
	db := got["DS-RAT-SEC-013"]
	if db.Code == "" || db.Deleted {
		t.Errorf("db uri: want live finding, got %+v", db)
	}
	// Config env and history secrets.
	if env := got["DS-RAT-SEC-014"]; env.Code == "" || env.Source != SourceImageEnv {
		t.Errorf("config env secret not found from env source: %+v", env)
	}
	if hist := got["DS-RAT-SEC-002"]; hist.Code == "" || hist.Source != SourceImageHistory {
		t.Errorf("history AWS secret not found from history source: %+v", hist)
	}
	// The UUID in main.py must not produce a finding.
	for _, d := range ds {
		if d.Path == "app/main.py" {
			t.Errorf("benign UUID in main.py produced a finding: %+v", d)
		}
	}
}

func TestScanImageDeterministic(t *testing.T) {
	s := New()
	a := s.ScanImage(context.Background(), buildLayeredImage())
	b := s.ScanImage(context.Background(), buildLayeredImage())
	if !reflect.DeepEqual(a, b) {
		t.Errorf("ScanImage over the same image is not deterministic:\n%+v\n%+v", a, b)
	}
}
