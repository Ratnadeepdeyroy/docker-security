package sig

import (
	"encoding/json"
	"testing"
)

func TestTransLogAppendAndVerify(t *testing.T) {
	logKey := mustSigner(AlgEd25519, "logkey")
	log := NewTransLog(logKey)

	entries := [][]byte{[]byte("env-0"), []byte("env-1"), []byte("env-2")}
	var recs []*InclusionRecord
	for _, e := range entries {
		rec, err := log.Append(e)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		recs = append(recs, rec)
	}

	// Every record must verify against the trusted log key with its own bytes.
	// Note each record's checkpoint is over the log state *at append time*, so we
	// verify each with the bytes we logged.
	for i, rec := range recs {
		if err := VerifyInclusion(rec, entries[i], logKey.Verifier()); err != nil {
			t.Fatalf("entry %d: VerifyInclusion: %v", i, err)
		}
	}
}

func TestTransLogRejectsTamper(t *testing.T) {
	logKey := mustSigner(AlgEd25519, "logkey2")
	log := NewTransLog(logKey)
	rec, err := log.Append([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	// Wrong logged bytes: hash mismatch.
	if err := VerifyInclusion(rec, []byte("different"), logKey.Verifier()); err == nil {
		t.Error("accepted mismatched logged bytes")
	}

	// Tampered root: signature no longer covers it.
	bad := *rec
	bad.Checkpoint.RootHash = "00" + rec.Checkpoint.RootHash[2:]
	if err := VerifyInclusion(&bad, []byte("payload"), logKey.Verifier()); err == nil {
		t.Error("accepted a tampered checkpoint root")
	}

	// Wrong log key: untrusted.
	other := mustSigner(AlgEd25519, "other-log")
	if err := VerifyInclusion(rec, []byte("payload"), other.Verifier()); err == nil {
		t.Error("accepted a checkpoint from an untrusted log key")
	}
}

// TestTransLogDeterministic: an ed25519-signed log yields identical checkpoint
// signatures for the same append sequence, so log state is reproducible.
func TestTransLogDeterministic(t *testing.T) {
	build := func() Checkpoint {
		log := NewTransLog(mustSigner(AlgEd25519, "det-log"))
		_, _ = log.Append([]byte("a"))
		_, _ = log.Append([]byte("b"))
		cp, err := log.Checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}
	a, b := build(), build()
	if a.RootHash != b.RootHash || a.Signature != b.Signature {
		t.Fatalf("transparency log not deterministic:\n%+v\n%+v", a, b)
	}
}

func TestInclusionRecordMarshalRoundTrip(t *testing.T) {
	log := NewTransLog(mustSigner(AlgEd25519, "marshal-log"))
	logKey := mustSigner(AlgEd25519, "marshal-log") // same seed -> same key
	rec, err := log.Append([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got InclusionRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(&got, []byte("data"), logKey.Verifier()); err != nil {
		t.Fatalf("verify after marshal round-trip: %v", err)
	}
}
