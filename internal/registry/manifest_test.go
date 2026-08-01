package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDigestMatchesSHA256(t *testing.T) {
	data := []byte("some content")
	sum := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got := Digest(data); got != want {
		t.Errorf("Digest = %s, want %s", got, want)
	}
}

func TestVerifyDigest(t *testing.T) {
	data := []byte("content")
	good := Digest(data)
	if err := VerifyDigest(data, good); err != nil {
		t.Errorf("VerifyDigest rejected matching content: %v", err)
	}
	if err := VerifyDigest([]byte("other"), good); err == nil {
		t.Error("VerifyDigest accepted mismatched content")
	}
}

func TestParseManifestSubject(t *testing.T) {
	data := []byte(`{
		"schemaVersion": 2,
		"mediaType": "` + MediaTypeOCIManifest + `",
		"artifactType": "application/vnd.docker-security.bundle.v1+json",
		"config": {"mediaType":"` + MediaTypeEmptyJSON + `","digest":"sha256:` + hex64('a') + `","size":2},
		"layers": [{"mediaType":"application/octet-stream","digest":"sha256:` + hex64('b') + `","size":10}],
		"subject": {"mediaType":"` + MediaTypeOCIManifest + `","digest":"sha256:` + hex64('c') + `"}
	}`)
	m, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.Subject == nil || m.Subject.Digest != "sha256:"+hex64('c') {
		t.Errorf("subject not parsed: %+v", m.Subject)
	}
	if m.ArtifactType == "" {
		t.Error("artifactType not parsed")
	}
}

func TestIsIndex(t *testing.T) {
	if !IsIndex(MediaTypeOCIIndex) || !IsIndex(MediaTypeDockerManifestList) {
		t.Error("index media types should be recognized")
	}
	if IsIndex(MediaTypeOCIManifest) {
		t.Error("a single manifest is not an index")
	}
}

func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
