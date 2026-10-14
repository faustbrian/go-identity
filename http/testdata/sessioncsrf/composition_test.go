// This external-consumer fixture is run from a disposable module with the HTTP
// and session modules selected explicitly. Base HTTP must not import session.
package sessioncsrf_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

func TestSessionOwnedCSRFCustody(t *testing.T) {
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{
		Limits:               identityhttp.Limits{MaximumHeaderBytes: 1024, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 10, MaximumDepth: 4},
		MaximumForwardedHops: 1,
		TenantHosts:          []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{
		Network: network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, RefererFallback: identityhttp.RefererFallbackDeny,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately synthetic non-secret bytes; no production credentials in fixtures.
	wire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	token, err := session.ParseCSRFToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewCSRFKey(3, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	binding := session.CSRFBinding{TenantID: "tenant-a", SessionID: "session-a", SessionVersion: 7}
	state, err := token.Digest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []bool{false, true} {
		body, media := `{"name":"sample"}`, "application/json"
		if form {
			body, media = "csrf_token="+wire+"&name=sample", "application/x-www-form-urlencoded"
		}
		r := httptest.NewRequest(http.MethodPost, "/mutation", strings.NewReader(body))
		r.Host = "tenant.example"
		r.RemoteAddr, r.TLS = "198.51.100.7:1234", &tls.ConnectionState{}
		r.Header.Set("Origin", "https://tenant.example")
		r.Header.Set("Content-Type", media)
		if !form {
			r.Header.Set("X-CSRF-Token", wire)
		}
		got, fields, err := identityhttp.DecodeCSRF(decoder, r, session.ParseCSRFToken)
		if err != nil || state.Check(binding, got, key) != nil {
			t.Fatal("owner credential lost during transport admission")
		}
		if form && (fields.Get("name") != "sample" || fields.Has("csrf_token")) {
			t.Fatal("form custody lost or credential retained")
		}
		if !form {
			requestDecoder, err := identityhttp.NewRequestDecoder(identityhttp.Limits{MaximumHeaderBytes: 1024, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 10, MaximumDepth: 4})
			if err != nil {
				t.Fatal(err)
			}
			input, err := identityhttp.DecodeJSON[struct {
				Name string `json:"name"`
			}](requestDecoder, r)
			if err != nil || input.Name != "sample" {
				t.Fatal("JSON no longer available to its owner")
			}
		}
		if fmt.Sprintf("%#v", got) != "[REDACTED]" {
			t.Fatal("opaque credential exposed")
		}
		if _, err := json.Marshal(got); err == nil {
			t.Fatal("credential serialized")
		}
		for _, change := range []func(*session.CSRFBinding){
			func(b *session.CSRFBinding) { b.TenantID = "tenant-b" },
			func(b *session.CSRFBinding) { b.SessionID = "session-b" },
			func(b *session.CSRFBinding) { b.SessionVersion++ },
		} {
			other := binding
			change(&other)
			if !errors.Is(state.Check(other, got, key), session.ErrCSRFDenied) {
				t.Fatal("transport token widened its binding")
			}
		}
		wrongKey, _ := session.NewCSRFKey(4, []byte(strings.Repeat("k", 32)))
		if !errors.Is(state.Check(binding, got, wrongKey), session.ErrCSRFDenied) {
			t.Fatal("unnamed key accepted")
		}
		if !errors.Is((session.CSRFState{}).Check(binding, got, key), session.ErrCSRFDenied) {
			t.Fatal("legacy absent state accepted")
		}
	}
	// Check is intentionally structural: primary validity, expiry and revocation
	// remain RequireCSRF's transactional responsibility, not a transport lease.
}
