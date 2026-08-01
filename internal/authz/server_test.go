package authz

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func post(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestActivationHandshake(t *testing.T) {
	srv := NewServer(&Policy{}, nil)
	rec := post(t, srv, "/Plugin.Activate", struct{}{})
	var got map[string][]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got["Implements"]) != 1 || got["Implements"][0] != "authz" {
		t.Errorf("activation should declare the authz capability, got %v", got)
	}
}

func TestAuthZReqDeniesPrivileged(t *testing.T) {
	srv := NewServer(&Policy{DenyPrivileged: true}, nil)
	body := base64.StdEncoding.EncodeToString([]byte(`{"HostConfig":{"Privileged":true}}`))
	rec := post(t, srv, "/AuthZPlugin.AuthZReq", authZReq{
		RequestMethod: "POST",
		RequestURI:    "/v1.43/containers/create",
		RequestBody:   body,
	})
	var res authZRes
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Allow {
		t.Fatalf("privileged create should be denied over the wire, got %+v", res)
	}
	if res.Err == "" {
		t.Errorf("deny response should carry an Err message")
	}
}

func TestAuthZReqAllowsBenign(t *testing.T) {
	srv := NewServer(&Policy{DenyPrivileged: true}, nil)
	body := base64.StdEncoding.EncodeToString([]byte(`{"HostConfig":{"Privileged":false}}`))
	rec := post(t, srv, "/AuthZPlugin.AuthZReq", authZReq{
		RequestMethod: "POST", RequestURI: "/containers/create", RequestBody: body,
	})
	var res authZRes
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !res.Allow {
		t.Errorf("benign create should be allowed over the wire, got %+v", res)
	}
}

func TestAuthZResAlwaysAllows(t *testing.T) {
	srv := NewServer(&Policy{ReadOnly: true}, nil)
	rec := post(t, srv, "/AuthZPlugin.AuthZRes", authZReq{RequestMethod: "POST", RequestURI: "/x"})
	var res authZRes
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !res.Allow {
		t.Errorf("post-response hook should always allow (enforcement is pre-request), got %+v", res)
	}
}
