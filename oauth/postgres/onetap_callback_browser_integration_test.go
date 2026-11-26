//go:build integration

package postgres

import (
	"encoding/base64"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOneTapCallbackRequiresOriginalBrowserCookie(t *testing.T) {
	ctx, pool, c, counter := oneTapStartIntegrationFixture(t)
	owner, err := NewOneTapStartService(pool, c)
	if err != nil {
		t.Fatal("create start owner", err)
	}
	start := func(key string) (OneTapBrowserStart, auth.BearerCredential) {
		t.Helper()
		_, req := oneTapStartIntegrationRequest(t, key)
		result, err := owner.Start(ctx, req)
		b, delivered := result.Browser()
		if err != nil || !delivered {
			t.Fatal("issue original browser flow", err)
		}
		wire, err := b.Token.Reveal()
		if err != nil {
			t.Fatal("deliver original flow cookie", err)
		}
		return b, auth.NewBearerCredential(wire)
	}
	flow, cookie := start("callback-browser-original")
	_, other := start("callback-browser-foreign")
	charged := counter.calls
	keys := map[uint32]session.DigestKey{1: c.Issuance.LookupKey}
	provider, original, digest, err := owner.readOneTapCallbackBrowser(ctx, flow.FlowID, cookie, keys)
	if err != nil || original.Transaction.Binding.ID != flow.FlowID || original.Provider != owner.selected || digest != original.Transaction.Cookie ||
		provider.CheckProvider(c.Issuance.Clock.Now().UTC(), original.Transaction.Binding, owner.selected, digest) != nil {
		t.Fatal("callback did not authenticate original provider browser", err)
	}
	for _, candidate := range []struct {
		name   string
		cookie auth.BearerCredential
		keys   map[uint32]session.DigestKey
	}{
		{"same-format foreign cookie", other, keys},
		{"malformed", auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString([]byte("invalid"))), keys},
		{"missing original version", cookie, nil},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			_, actual, d, err := owner.readOneTapCallbackBrowser(ctx, flow.FlowID, candidate.cookie, candidate.keys)
			var denied identity.ForbiddenError
			if !errors.As(err, &denied) || actual.Transaction.Binding.ID != "" || d != (session.TokenDigest{}) {
				t.Fatal("invalid original cookie returned browser custody", err)
			}
		})
	}
	if counter.calls != charged {
		t.Fatal("read-only browser validation charged risk before execution")
	}
}
