//go:build ignore

// Command gen is an evidence/demo harness for the harden module. It is not part
// of the package build (the ignore tag + the testdata/ location both exclude it);
// run it explicitly to reproduce the command output pasted into PHASE-7-REPORT.md:
//
//	go run internal/modules/harden/testdata/gen/main.go
package main

import (
	"fmt"

	harden "github.com/Ratnadeepdeyroy/docker-security/internal/modules/harden"
)

func main() {
	obs := "internal/modules/harden/testdata/observation.json"
	pod := "internal/modules/harden/testdata/privileged.pod.json"

	fmt.Println("$ dsecrat harden gen-profile --from observation.json --type seccomp")
	harden.Command([]string{"gen-profile", "--from", obs, "--type", "seccomp"})

	fmt.Println("\n$ dsecrat harden gen-profile --from observation.json --type apparmor --name payments-api")
	harden.Command([]string{"gen-profile", "--from", obs, "--type", "apparmor", "--name", "payments-api"})

	fmt.Println("\n$ dsecrat harden verify internal/modules/harden/testdata/privileged.pod.json --trust untrusted")
	harden.Command([]string{"verify", "--trust", "untrusted", pod})

	fmt.Println("\n$ dsecrat harden verify --bundle --observation observation.json --now 2026-07-04T00:00:00Z privileged.pod.json")
	harden.Command([]string{"verify", "--bundle", "--observation", obs, "--now", "2026-07-04T00:00:00Z", pod})
}
