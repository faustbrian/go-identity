package anonymous_test

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	"github.com/faustbrian/go-identity/session"
)

func deletionRequest(t testing.TB) anonymous.DeletionRequest {
	t.Helper()
	r := signinRequest(t)
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	return anonymous.DeletionRequest{TenantID: r.TenantID, Credential: credential, CSRFToken: csrf, ExpectedVersion: 1, Reason: "self-request", Origin: r.Origin, Network: r.Network, Device: r.Device, IdempotencyKey: r.IdempotencyKey}
}

func TestDeletionRequestBoundsOriginalSelfPossession(t *testing.T) {
	r := deletionRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid self request", err)
	}
	for _, mutate := range []func(*anonymous.DeletionRequest){
		func(r *anonymous.DeletionRequest) { r.TenantID = "" },
		func(r *anonymous.DeletionRequest) { r.Credential = session.Credential{} },
		func(r *anonymous.DeletionRequest) { r.CSRFToken = session.CSRFToken{} },
		func(r *anonymous.DeletionRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *anonymous.DeletionRequest) { r.ExpectedVersion = 0 },
		func(r *anonymous.DeletionRequest) { r.ExpectedVersion = math.MaxUint64 },
		func(r *anonymous.DeletionRequest) { r.Reason = "" },
		func(r *anonymous.DeletionRequest) { r.Reason = strings.Repeat("a", 65) },
		func(r *anonymous.DeletionRequest) { r.Reason = "self\nrequest" },
		func(r *anonymous.DeletionRequest) { r.Origin = "https://example.test\n" },
		func(r *anonymous.DeletionRequest) { r.Origin = strings.Repeat("a", 2049) },
		func(r *anonymous.DeletionRequest) { r.Network = "192.0.2.001" },
		func(r *anonymous.DeletionRequest) { r.Network = "fe80::1%en0" },
		func(r *anonymous.DeletionRequest) { r.Device = strings.Repeat("a", 129) },
	} {
		changed := r
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid original request admitted")
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatal("validation consumed or mutated original possession", err)
	}
}

func TestDeletionRequestDoesNotDiscloseOrConsumeCredentials(t *testing.T) {
	r := deletionRequest(t)
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("request implicitly serialized")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d"} {
		text := fmt.Sprintf(format, r)
		if strings.Contains(text, r.Origin) || strings.Contains(text, r.Network) || strings.Contains(text, r.Reason) {
			t.Fatal("request diagnostics exposed custody")
		}
	}
	if _, err := r.CSRFToken.Reveal(); err != nil {
		t.Fatal("validation or formatting consumed CSRF", err)
	}
	if r.Credential.Kind() != session.CredentialCookie {
		t.Fatal("validation changed original transport")
	}
}
