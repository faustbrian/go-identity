package mfa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func uriRequestFixture(t *testing.T) TotpUriRequest {
	t.Helper()
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	return TotpUriRequest{TenantID: "tenant-a", EnrollmentID: "AAAAAAAAAAAAAAAAAAAAAQ", CommandID: "AAAAAAAAAAAAAAAAAAAAAg", Session: auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), CSRFToken: csrf, Origin: "https://app.test", Network: "192.0.2.1", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant-a", Action: "identity.mfa.totp-uri", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user-a"}, Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}}}
}

func TestTOTPURIInputRequiresStableEnrollmentAndAuthenticatedCSRFContext(t *testing.T) {
	r := uriRequestFixture(t)
	if r.Validate() != nil {
		t.Fatal("valid URI reveal input denied")
	}
	for _, mutate := range []func(*TotpUriRequest){
		func(r *TotpUriRequest) { r.TenantID = "" }, func(r *TotpUriRequest) { r.CommandID = identity.CommandID(r.EnrollmentID) }, func(r *TotpUriRequest) { r.CommandID = "bad" }, func(r *TotpUriRequest) { r.EnrollmentID = "bad" }, func(r *TotpUriRequest) { r.Session = auth.BearerCredential{} }, func(r *TotpUriRequest) { r.CSRFToken = session.CSRFToken{} }, func(r *TotpUriRequest) { r.Origin = "https://app.test/path" }, func(r *TotpUriRequest) { r.Network = "not-ip" }, func(r *TotpUriRequest) { r.Caller.Request.Action = "identity.mfa.enable" }, func(r *TotpUriRequest) { r.Caller.Request.Tenant = "foreign" }, func(r *TotpUriRequest) { r.Caller.Request.Resource.ID = "foreign" },
	} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("malformed or foreign reveal scope accepted")
		}
	}
}

func TestTOTPURIContractsRedactBorrowedAndRevealOnceMaterial(t *testing.T) {
	r := uriRequestFixture(t)
	for _, value := range []any{r, TotpUriResult{URI: RevealOnceURI{URI: "otpauth://totp/sensitive-fixture"}}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(verb, value)
			if !strings.Contains(text, "redacted") || strings.Contains(text, "sensitive-fixture") {
				t.Fatal("URI contract leaked custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit URI contract export accepted")
		}
	}
}

func TestTOTPURIValidationDoesNotConsumeBorrowedSynchronizer(t *testing.T) {
	r := uriRequestFixture(t)
	for range 3 {
		if err := r.Validate(); err != nil {
			t.Fatal("validation consumed borrowed synchronizer custody")
		}
	}
	if _, err := r.CSRFToken.Reveal(); err != nil {
		t.Fatal("validation consumed transport-owned delivery permission")
	}
}
