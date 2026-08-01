// Package admission is the Kubernetes ValidatingWebhook half of Phase 4. It
// receives an AdmissionReview, projects the pod's security-relevant fields into
// the shared policy Input, evaluates the same internal/policy engine the CI gate
// uses, and answers allow or deny — so a rule blocks a bad workload before it
// runs, not just in a pipeline.
//
// Two design rules matter most. It is offline and cluster-free: the wire types
// are re-implemented here (no Kubernetes client dependency), and every test
// drives recorded AdmissionReview fixtures, never a live API server. And it
// fails closed: an unparseable object or an evaluation error denies by default,
// because a webhook that errors open is a webhook an attacker races.
package admission

import "encoding/json"

// --- Kubernetes admission/v1 wire types ------------------------------------
//
// These mirror the stable JSON shape of admission.k8s.io/v1. We hand-roll them
// rather than import k8s.io/api both to honor the "re-implement, don't depend"
// rule and to keep the webhook a tiny, auditable binary.

// AdmissionReview is the top-level request/response envelope.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest is the review's request half (what the API server asks about).
type AdmissionRequest struct {
	UID       string               `json:"uid"`
	Kind      GroupVersionKind     `json:"kind"`
	Resource  GroupVersionResource `json:"resource"`
	Name      string               `json:"name,omitempty"`
	Namespace string               `json:"namespace,omitempty"`
	Operation string               `json:"operation,omitempty"`
	// Object is the raw resource being admitted (a Pod, Deployment, …).
	Object json.RawMessage `json:"object,omitempty"`
}

// AdmissionResponse is the webhook's verdict.
type AdmissionResponse struct {
	UID      string   `json:"uid"`
	Allowed  bool     `json:"allowed"`
	Status   *Status  `json:"status,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// AuditAnnotations surface structured detail into the API-server audit log;
	// we use it to attach the machine-readable policy decision.
	AuditAnnotations map[string]string `json:"auditAnnotations,omitempty"`
}

// Status carries the human/HTTP-style reason shown to the user on a deny.
type Status struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// GroupVersionKind identifies the object's kind.
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// GroupVersionResource identifies the object's resource type.
type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

const (
	admissionAPIVersion = "admission.k8s.io/v1"
	admissionKind       = "AdmissionReview"
)

// newResponseReview wraps a response in a fresh review envelope with the correct
// apiVersion/kind, as the API server requires on the way back.
func newResponseReview(resp *AdmissionResponse) *AdmissionReview {
	return &AdmissionReview{APIVersion: admissionAPIVersion, Kind: admissionKind, Response: resp}
}
