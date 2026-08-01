package runtime

import "testing"

func TestPersistenceRuleFiresOnLdSoPreloadWrite(t *testing.T) {
	ev := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/etc/ld.so.preload", Op: "write"}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-011") {
		t.Fatalf("want DS-RAT-RT-011 on ld.so.preload write")
	}
}
func TestPersistenceRuleFiresOnAuthorizedKeysWrite(t *testing.T) {
	ev := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/home/app/.ssh/authorized_keys", Op: "write"}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-011") {
		t.Fatalf("want DS-RAT-RT-011 on authorized_keys write")
	}
}
func TestPersistenceRuleFiresOnLdPreloadEnv(t *testing.T) {
	ev := Event{Kind: KindProcess, Seq: 1, Process: ProcessInfo{Exe: "/bin/sh", Args: []string{"sh", "-c", "LD_PRELOAD=/tmp/evil.so id"}}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-011") {
		t.Fatalf("want DS-RAT-RT-011 on LD_PRELOAD env")
	}
}
func TestPersistenceRuleIgnoresBenignWriteAndRead(t *testing.T) {
	w := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/tmp/scratch", Op: "write"}}
	r := Event{Kind: KindFile, Seq: 2, File: &FileEvent{Path: "/etc/ld.so.preload", Op: "read"}}
	if fired(evalOne(t, Options{}, nil, w), "DS-RAT-RT-011") {
		t.Fatalf("false positive on /tmp write")
	}
	if fired(evalOne(t, Options{}, nil, r), "DS-RAT-RT-011") {
		t.Fatalf("false positive on ld.so.preload READ")
	}
}
