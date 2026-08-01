package kubebench

import "github.com/Ratnadeepdeyroy/docker-security/internal/compliance"

// --- Section 2 checks: etcd ------------------------------------------------
//
// etcd stores all cluster state (including Secrets), so its transport security
// is critical. Checks read etcd's effective flags; uncollected flags degrade to
// INFO.

func (e *Evidence) noEtcd() (compliance.Assessment, bool) {
	if !e.Etcd.hasFlags() {
		return info("etcd flags not collected; cannot assess"), true
	}
	return compliance.Assessment{}, false
}

func check21EtcdServerTLS(e *Evidence) compliance.Assessment {
	if a, skip := e.noEtcd(); skip {
		return a
	}
	if e.Etcd.present("cert-file") && e.Etcd.present("key-file") {
		return pass("etcd server TLS cert and key are configured")
	}
	return fail("etcd server TLS (--cert-file/--key-file) is not fully configured", "missing cert-file/key-file")
}

func check22EtcdClientCertAuth(e *Evidence) compliance.Assessment {
	if a, skip := e.noEtcd(); skip {
		return a
	}
	if flagIsTrue(e.Etcd, "client-cert-auth") {
		return pass("etcd requires client certificate authentication")
	}
	return fail("etcd client certificate authentication is not enabled", flagOrNA(e.Etcd, "client-cert-auth"))
}

func check23EtcdAutoTLS(e *Evidence) compliance.Assessment {
	if a, skip := e.noEtcd(); skip {
		return a
	}
	if flagIsTrue(e.Etcd, "auto-tls") {
		return fail("etcd --auto-tls is enabled (self-signed certs accepted)", "true")
	}
	return pass("etcd --auto-tls is not enabled")
}

func check24EtcdPeerTLS(e *Evidence) compliance.Assessment {
	if a, skip := e.noEtcd(); skip {
		return a
	}
	if e.Etcd.present("peer-cert-file") && e.Etcd.present("peer-key-file") {
		return pass("etcd peer TLS cert and key are configured")
	}
	return fail("etcd peer TLS (--peer-cert-file/--peer-key-file) is not fully configured", "missing peer cert/key")
}

func check25EtcdPeerClientCertAuth(e *Evidence) compliance.Assessment {
	if a, skip := e.noEtcd(); skip {
		return a
	}
	if flagIsTrue(e.Etcd, "peer-client-cert-auth") {
		return pass("etcd requires peer client certificate authentication")
	}
	return fail("etcd peer client certificate authentication is not enabled", flagOrNA(e.Etcd, "peer-client-cert-auth"))
}

func check26EtcdPeerAutoTLS(e *Evidence) compliance.Assessment {
	if a, skip := e.noEtcd(); skip {
		return a
	}
	if flagIsTrue(e.Etcd, "peer-auto-tls") {
		return fail("etcd --peer-auto-tls is enabled", "true")
	}
	return pass("etcd --peer-auto-tls is not enabled")
}
