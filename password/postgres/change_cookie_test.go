package passwordpostgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

// The cookie profile must use the session owner's exact named-key check, not
// token presence or a fallback key. This local test is not a primary fence proof.
func TestPasswordCookieCheckRequiresExactSessionState(t *testing.T) {
	token, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewCSRFKey(7, bytes.Repeat([]byte{18}, 32))
	if err != nil {
		t.Fatal(err)
	}
	binding := session.CSRFBinding{TenantID: "tenant", SessionID: "session", SessionVersion: 3}
	state, err := token.Digest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	profile := passwordChangeCSRF{keys: []session.CSRFKey{key}}
	if err := profile.check(state, binding, token); err != nil {
		t.Fatal(err)
	}
	wrong, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []session.CSRFToken{{}, wrong} {
		if profile.check(state, binding, candidate) == nil {
			t.Fatal("absent/foreign token admitted")
		}
	}
	foreign := binding
	foreign.SessionVersion++
	if profile.check(state, foreign, token) == nil {
		t.Fatal("foreign version admitted")
	}
	if profile.check(session.CSRFState{}, binding, token) == nil {
		t.Fatal("tokenless session admitted")
	}
	if (passwordChangeCSRF{}).check(state, binding, token) == nil {
		t.Fatal("unconfigured profile admitted")
	}
	otherKey, _ := session.NewCSRFKey(8, bytes.Repeat([]byte{18}, 32))
	if (passwordChangeCSRF{keys: []session.CSRFKey{otherKey}}).check(state, binding, token) == nil {
		t.Fatal("unnamed key fallback admitted")
	}
}
