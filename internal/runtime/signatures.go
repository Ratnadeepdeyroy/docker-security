package runtime

import (
	"path"
	"strings"
)

// This file holds the shared, data-driven signatures the rules match against.
// Keeping them in one place makes the detection surface auditable at a glance
// and easy to tune without touching rule logic.

// --- Shells & interpreters -----------------------------------------------

// shellBinaries are executables that give an interactive/scriptable shell. A
// service image spawning one is the classic post-exploitation pivot.
var shellBinaries = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "ash": {}, "zsh": {}, "ksh": {},
	"csh": {}, "tcsh": {}, "fish": {}, "busybox": {},
}

// isShell reports whether an exe path or comm is a shell.
func isShell(exe, comm string) bool {
	if _, ok := shellBinaries[path.Base(exe)]; ok {
		return true
	}
	_, ok := shellBinaries[comm]
	return ok
}

// --- Container-escape primitives -----------------------------------------

// escapeBinaries are tools whose very execution inside a container is a strong
// escape/priv-esc signal.
var escapeBinaries = map[string]struct{}{
	"nsenter": {}, "unshare": {}, "setns": {}, "docker": {}, "ctr": {},
	"runc": {}, "crictl": {}, "kubectl": {}, "capsh": {},
}

// escapeSyscalls are syscalls used to break container isolation.
var escapeSyscalls = map[string]struct{}{
	"setns": {}, "unshare": {}, "mount": {}, "pivot_root": {}, "chroot": {},
}

// hostEscapePaths are host locations whose access from inside a container
// indicates an escape attempt (host root, container socket, cgroup release).
var hostEscapePaths = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/var/run/containerd/containerd.sock", "/run/containerd/containerd.sock",
	"/proc/1/root", "/proc/sys/kernel/core_pattern",
	"/sys/fs/cgroup/release_agent", "/sys/kernel/uevent_helper",
	"/host", "/rootfs",
}

// --- Sensitive files (FIM) & credential locations ------------------------

// sensitiveReadPaths are files whose read is credential access or recon. It is
// kept deliberately tight to avoid false positives: broad trees like /home are
// NOT listed — private key material anywhere (incl. /home/*/.ssh) is caught by
// isSSHKeyPath instead, so we flag the high-signal case without the noise.
var sensitiveReadPaths = []string{
	"/etc/shadow", "/etc/gshadow",
	"/root/.ssh/",
	"/proc/kcore",
}

// credentialPaths are secrets whose read is high-signal credential theft.
var credentialPaths = []string{
	"/var/run/secrets/kubernetes.io/serviceaccount/token", // k8s SA token
	"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	"/root/.aws/credentials", "/root/.docker/config.json",
	"/root/.kube/config",
}

// sensitiveWritePaths are files whose modification is tampering/persistence.
var sensitiveWritePaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/",
	"/etc/cron", "/var/spool/cron", "/etc/ld.so.preload",
	"/root/.ssh/authorized_keys", "/etc/ssh/",
}

// isSSHKeyPath flags reads of private SSH key material anywhere under a .ssh dir.
func isSSHKeyPath(p string) bool {
	return strings.Contains(p, "/.ssh/") &&
		(strings.HasSuffix(p, "id_rsa") || strings.HasSuffix(p, "id_ed25519") ||
			strings.HasSuffix(p, "id_ecdsa") || strings.HasSuffix(p, "identity"))
}

// matchesAnyPrefix reports whether p starts with any of the prefixes. A prefix
// ending in "/" matches a directory subtree; otherwise it matches exactly or as
// a path prefix boundary.
func matchesAnyPrefix(p string, prefixes []string) (string, bool) {
	clean := path.Clean(p)
	for _, pre := range prefixes {
		if strings.HasSuffix(pre, "/") {
			if strings.HasPrefix(clean, pre) || clean == strings.TrimSuffix(pre, "/") {
				return pre, true
			}
		} else if clean == pre || strings.HasPrefix(clean, pre+"/") {
			return pre, true
		}
	}
	return "", false
}

// --- Cloud metadata (IMDS) -----------------------------------------------

// imdsIPs are cloud instance-metadata endpoints. Egress to these from a
// workload that should not need them is textbook credential theft (T1552.005).
var imdsIPs = map[string]struct{}{
	"169.254.169.254": {}, // AWS/GCP/Azure/OpenStack IMDS
	"100.100.100.200": {}, // Alibaba Cloud
	"fd00:ec2::254":   {}, // AWS IMDSv2 IPv6
}

// imdsDomains are DNS names that resolve to metadata services.
var imdsDomains = map[string]struct{}{
	"metadata.google.internal": {},
	"metadata.goog":            {},
	"instance-data":            {},
	"metadata":                 {},
}

// --- Crypto-mining --------------------------------------------------------

// minerBinaries are known miner process names.
var minerBinaries = map[string]struct{}{
	"xmrig": {}, "minerd": {}, "cpuminer": {}, "cgminer": {}, "bfgminer": {},
	"ethminer": {}, "nheqminer": {}, "xmr-stak": {}, "t-rex": {}, "phoenixminer": {},
}

// minerArgTokens are strings in argv that betray mining regardless of the binary
// name (miners are routinely renamed to evade name-based detection).
var minerArgTokens = []string{
	"stratum+tcp://", "stratum+ssl://", "--donate-level", "--coin=monero",
	"nicehash", "randomx", "--cpu-priority", "-o pool.",
}

// looksLikeMiner reports whether a process is a crypto-miner by name or argv.
func looksLikeMiner(exe, comm string, args []string) (reason string, ok bool) {
	base := path.Base(exe)
	if _, hit := minerBinaries[base]; hit {
		return "miner binary " + base, true
	}
	if _, hit := minerBinaries[comm]; hit {
		return "miner process " + comm, true
	}
	joined := strings.ToLower(strings.Join(args, " "))
	for _, tok := range minerArgTokens {
		if strings.Contains(joined, tok) {
			return "mining argument " + tok, true
		}
	}
	return "", false
}

// --- Kernel abuse --------------------------------------------------------

// kernelModuleSyscalls load/unload kernel modules — a rootkit installation path.
var kernelModuleSyscalls = map[string]struct{}{
	"init_module": {}, "finit_module": {}, "delete_module": {},
}

// --- Redaction -----------------------------------------------------------

// redactArgs returns argv with secret-shaped tokens masked, so nothing sensitive
// is ever written to a finding, log, or forensic bundle (SHARED_CONTRACT §7).
func redactArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = redactToken(a)
	}
	return out
}

// redactToken masks a single token if it looks like a credential (a long
// high-entropy-ish blob, or a key=value where the key is sensitive).
func redactToken(tok string) string {
	if k, v, ok := strings.Cut(tok, "="); ok && isSensitiveKey(k) && v != "" {
		return k + "=***"
	}
	// Heuristic: long, no spaces, mixed alnum → likely a token/secret.
	if len(tok) >= 32 && !strings.ContainsAny(tok, " /\\") && looksHighEntropy(tok) {
		return "***"
	}
	return tok
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(strings.TrimLeft(k, "-"))
	for _, s := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "key", "credential"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// looksHighEntropy is a cheap check: a token with a healthy mix of letter and
// digit/symbol classes. Not cryptographic — just enough to avoid masking plain
// words while catching base64-ish secrets.
func looksHighEntropy(s string) bool {
	var letters, digits, other int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letters++
		default:
			other++
		}
	}
	return digits > 0 && letters > 0 && (digits+other) >= len(s)/6
}
