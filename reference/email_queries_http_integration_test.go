//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresEmailQueriesHTTPS(t *testing.T) {
	_ = reference.HTTPEmailAddressesConfiguration{Get: true, List: true}
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailAddressQueries: true, emailChangeCase: "queries-http"})
}

func TestReferencePostgresEmailQueriesStandaloneHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailAddressQueries: true, emailChangeCase: "queries-standalone-http"})
}

func TestReferencePostgresEmailGetOnlyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailAddressQueries: true, emailChangeCase: "queries-get-http"})
}

// Actual native registration, delivered verification and signin precede all
// requests. Session/rate/query ownership comes only from reference composition.
func proveReferenceEmailQueriesHTTPS(t *testing.T, ctx context.Context, f liveStores, client *http.Client, base string, cookies []*http.Cookie, user identity.UserID, address identity.IdentifierID, list bool) {
	t.Helper()
	for _, mode := range []string{"list", "get", "missing", "cookie", "authorization", "key", "user", "duplicate", "limit", "cursor", "body", "host", "method", "duplicate-cookie"} {
		path, want := "/v1/email/address-get?addressID="+url.QueryEscape(string(address)), 200
		var reader io.Reader
		switch mode {
		case "list":
			path = "/v1/email/address-list?limit=1"
			if !list {
				want = 404
			}
		case "missing":
			path = "/v1/email/address-get?addressID=not-owned-address"
			want = 403
		case "cookie":
			want = 403
		case "authorization", "key", "body", "duplicate-cookie":
			want = 400
		case "user":
			path += "&userID=other"
			want = 400
		case "duplicate":
			path += "&addressID=other"
			want = 400
		case "limit":
			path = "/v1/email/address-list?limit=101"
			want = 400
			if !list {
				want = 404
			}
		case "cursor":
			path = "/v1/email/address-list?cursor=invalid"
			want = 400
			if !list {
				want = 404
			}
		case "host":
			want = 421
		case "method":
			want = 405
		}
		if mode == "body" {
			reader = strings.NewReader("{}")
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if mode != "cookie" {
			for _, cookie := range cookies {
				r.AddCookie(cookie)
			}
		}
		if mode == "authorization" {
			r.Header.Set("Authorization", "Bearer synthetic-forbidden-alternative")
		}
		if mode == "key" {
			r.Header.Set("Idempotency-Key", "synthetic-read-key")
		}
		if mode == "duplicate-cookie" {
			r.AddCookie(cookies[0])
		}
		if mode == "host" {
			r.Host = "foreign.example"
		}
		if mode == "method" {
			r.Method = http.MethodPost
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("actual email read HTTPS", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > 1<<20 || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("email read HTTP boundary", mode, response.StatusCode)
		}
		if want != 200 {
			if strings.Contains(string(body), "registered@example.invalid") || strings.Contains(string(body), string(user)) || strings.Contains(string(body), string(address)) {
				t.Fatal("read denial disclosed address or identity", mode)
			}
			clear(body)
			continue
		}
		var views []emailhttp.AddressView
		if mode == "list" {
			var out struct {
				Addresses  []emailhttp.AddressView `json:"addresses"`
				NextCursor string                  `json:"nextCursor"`
			}
			if json.Unmarshal(body, &out) != nil || out.NextCursor != "" {
				t.Fatal("native email list projection")
			}
			views = out.Addresses
		} else {
			var out struct {
				Address emailhttp.AddressView `json:"address"`
			}
			if json.Unmarshal(body, &out) != nil {
				t.Fatal("native email get projection")
			}
			views = []emailhttp.AddressView{out.Address}
		}
		clear(body)
		if len(views) != 1 || views[0].UserID != user || views[0].IdentifierID != address || !views[0].Verified || views[0].IdentifierVersion != 2 || views[0].VerificationVersion != 2 || views[0].Canonical != "registered@example.invalid" {
			t.Fatal("read transport changed actual native email history", mode)
		}
	}
	var count int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND verified AND version=2 AND verification_version=2`, otpTenant, string(user), string(address)).Scan(&count); err != nil || count != 1 {
		t.Fatal("read requests mutated original address", err)
	}
}
