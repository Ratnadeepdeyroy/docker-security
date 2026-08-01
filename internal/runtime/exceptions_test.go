package runtime

import "testing"

func TestExceptionSuppressesByImage(t *testing.T) {
	es := &ExceptionSet{Rules: []Exception{{RuleID: "DS-RAT-RT-001", ImageRef: "ci/runner:1"}}}
	hit := Detection{RuleID: "DS-RAT-RT-001", Container: ContainerInfo{ImageRef: "ci/runner:1"}}
	miss := Detection{RuleID: "DS-RAT-RT-001", Container: ContainerInfo{ImageRef: "prod/api:9"}}
	if !es.Suppressed(hit) {
		t.Fatalf("should suppress CI runner shell")
	}
	if es.Suppressed(miss) {
		t.Fatalf("must not suppress prod shell")
	}
}

func TestExceptionRequiresRuleMatch(t *testing.T) {
	es := &ExceptionSet{Rules: []Exception{{RuleID: "DS-RAT-RT-004", PathPrefix: "/var/log/app/"}}}
	d := Detection{RuleID: "DS-RAT-RT-001", Metadata: map[string]string{"path": "/var/log/app/x"}}
	if es.Suppressed(d) {
		t.Fatalf("different rule id must not be suppressed")
	}
}

func TestLoadExceptionsFromTestdata(t *testing.T) {
	es, err := LoadExceptions("testdata/exceptions-sample.json")
	if err != nil || len(es.Rules) != 2 {
		t.Fatalf("load failed: %v (rules=%d)", err, len(es.Rules))
	}
}

func TestNilExceptionSetSuppressesNothing(t *testing.T) {
	var es *ExceptionSet
	if es.Suppressed(Detection{RuleID: "DS-RAT-RT-001"}) {
		t.Fatalf("nil set must suppress nothing")
	}
}
