package kubebench

import (
	"fmt"
	"strconv"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Assessment constructors -----------------------------------------------
//
// Terse wrappers that keep the many check functions readable.

func pass(evidence string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusPass, Evidence: evidence}
}
func warn(evidence, actual string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusWarn, Evidence: evidence, Actual: actual}
}
func fail(evidence, actual string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusFail, Evidence: evidence, Actual: actual}
}
func info(evidence string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusInfo, Evidence: evidence}
}

// --- File permission/ownership checks --------------------------------------

// checkOwnership assesses a file's owner:group against the expected pair.
func checkOwnership(e *Evidence, path, wantOwner, wantGroup string) compliance.Assessment {
	fs, ok := e.file(path)
	if !ok {
		return info(fmt.Sprintf("ownership of %s not collected", path))
	}
	if !fs.Exists {
		return info(fmt.Sprintf("%s does not exist on this node", path))
	}
	if fs.Owner == wantOwner && fs.Group == wantGroup {
		return pass(fmt.Sprintf("%s owned by %s:%s", path, fs.Owner, fs.Group))
	}
	return fail(fmt.Sprintf("%s should be owned by %s:%s", path, wantOwner, wantGroup),
		fmt.Sprintf("%s:%s", fs.Owner, fs.Group))
}

// checkPermsAtMost asserts a file's mode carries no bits outside maxMode.
func checkPermsAtMost(e *Evidence, path string, maxMode uint32) compliance.Assessment {
	fs, ok := e.file(path)
	if !ok {
		return info(fmt.Sprintf("permissions of %s not collected", path))
	}
	if !fs.Exists {
		return info(fmt.Sprintf("%s does not exist on this node", path))
	}
	mode, err := parseMode(fs.Mode)
	if err != nil {
		return info(fmt.Sprintf("unparseable mode %q for %s", fs.Mode, path))
	}
	if mode&^maxMode == 0 {
		return pass(fmt.Sprintf("%s permissions %04o within %04o", path, mode, maxMode))
	}
	return fail(fmt.Sprintf("%s permissions %04o are looser than %04o", path, mode, maxMode),
		fmt.Sprintf("%04o", mode))
}

// parseMode parses an octal mode string ("0600", "600", "0o600") into its
// permission bits (low 12 bits kept).
func parseMode(s string) (uint32, error) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'o' || s[1] == 'O') {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n) & 0o7777, nil
}
