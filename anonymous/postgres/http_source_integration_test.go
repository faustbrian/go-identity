//go:build integration

package anonymouspostgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	"github.com/faustbrian/go-identity/session"
)

// This is the native source of the anonymous flow rate dimension, not a
// transport-selected identifier. The original credential authenticates the
// stable rate scope even after consumption, without making the flow live again.
func TestNativeAnonymousSigninHTTPRateSourceRetainsOriginalPossession(t *testing.T) {
	type source interface {
		SigninRateSource(context.Context, anonymous.SigninRequest) (string, error)
	}
	if _, ok := any((*anonymouspg.SigninService)(nil)).(source); !ok {
		t.Fatal("native anonymous signin lacks the authenticated HTTP rate-source port")
	}
	f := newPublicAnonymousFixture(t)
	r := f.fresh()
	owner := any(f.service).(source)
	counts := func() [3]int {
		t.Helper()
		var out [3]int
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM anonymous_store.subjects),(SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity.commands)`).Scan(&out[0], &out[1], &out[2])
		if err != nil {
			t.Fatal("rate-source effect observation", err)
		}
		return out
	}
	before := counts()
	first, err := owner.SigninRateSource(f.ctx, r)
	if err != nil || first == "" || strings.Contains(first, r.Cookie.Token()) || counts() != before {
		t.Fatal("native flow source absent, disclosed credential or mutated identity state", err)
	}
	for _, mode := range []string{"foreign-cookie", "foreign-tenant", "wrong-origin", "wrong-callback", "wrong-remember", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			bad, ctx := r, f.ctx
			switch mode {
			case "foreign-cookie":
				token, err := session.NewToken(32)
				if err != nil {
					t.Fatal(err)
				}
				wire, _ := token.Reveal()
				bad.Cookie = auth.NewBearerCredential(wire)
			case "foreign-tenant":
				bad.TenantID = "tenant-b"
			case "wrong-origin":
				bad.Origin = "https://other.example"
			case "wrong-callback":
				bad.CallbackURL = "https://other.example/callback"
			case "wrong-remember":
				p, _ := bad.Remember.Bindings()
				p.AbsoluteTTL /= 2
				bad.Remember, err = session.NewRememberPolicy(p)
				if err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if value, err := owner.SigninRateSource(ctx, bad); err == nil || value != "" || counts() != before {
				t.Fatal("unproven flow selected a rate subject or performed domain work")
			}
		})
	}
	issued, err := f.service.Signin(f.ctx, r)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real signin prerequisite", err)
	}
	after := counts()
	if value, err := owner.SigninRateSource(f.ctx, r); err != nil || value != first || counts() != after {
		t.Fatal("consumed original scope changed, renewed authority or mutated state", err)
	}
	var zero *anonymouspg.SigninService
	if value, err := any(zero).(source).SigninRateSource(f.ctx, r); !errors.Is(err, anonymous.ErrInvalidInput) || value != "" {
		t.Fatal("nil source granted custody")
	}
}
