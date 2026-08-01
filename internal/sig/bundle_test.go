package sig

import "testing"

func TestBundleRoundTrip(t *testing.T) {
	signer := mustSigner(AlgEd25519, "bundle")
	log := NewTransLog(mustSigner(AlgEd25519, "bundle-log"))

	payload, _ := NewImagePayload("app", testDigest, nil)
	env, err := SignEnvelope(SimpleSigningMediaType, payload, signer)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, _ := env.Marshal()
	inc, err := log.Append(envBytes)
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewBundle(testDigest)
	if err != nil {
		t.Fatal(err)
	}
	b.AddSignature(env, inc)

	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if got.SubjectDigest != testDigest {
		t.Errorf("subject digest = %q", got.SubjectDigest)
	}
	if len(got.Entries) != 1 || got.Entries[0].Envelope == nil {
		t.Fatalf("bundle entries lost in round-trip: %+v", got.Entries)
	}
	if err := got.Entries[0].Envelope.VerifyWith(signer.Verifier()); err != nil {
		t.Errorf("envelope from parsed bundle failed verify: %v", err)
	}
}

func TestBundleRejectsBadDigest(t *testing.T) {
	if _, err := NewBundle("not-a-digest"); err == nil {
		t.Error("NewBundle accepted a malformed digest")
	}
	if _, err := ParseBundle([]byte(`{"subjectDigest":"bad","entries":[]}`)); err == nil {
		t.Error("ParseBundle accepted a malformed subject digest")
	}
}
