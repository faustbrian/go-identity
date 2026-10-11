package reference

import (
	"bytes"
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestSessionSelectionRequiresNativeOwners(t *testing.T) {
	if owner, err := composeSession(StoreConfiguration{}, ReferenceDependencies{}); err != nil || owner != nil {
		t.Fatal("unselected sessions acquired dependencies", err)
	}
	c := StoreConfiguration{Session: &SessionConfiguration{}}
	if owner, err := composeSession(c, ReferenceDependencies{}); err == nil || owner != nil {
		t.Fatal("selected sessions accepted absent native authority")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected sessions silently disappeared without a graph")
	}
}

func TestSessionSelectionMatchesIssuedKeyMaterial(t *testing.T) {
	lookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{1}, 32))
	older, _ := session.NewDigestKey(1, bytes.Repeat([]byte{3}, 32))
	copyLookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{1}, 32))
	wrongLookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{4}, 32))
	csrf, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{2}, 32))
	copyCSRF, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{2}, 32))
	wrongCSRF, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{5}, 32))
	p := passwordpg.SigninConfig{Issuance: session.IssuerConfig{LookupKey: lookup}, CSRFKey: csrf}
	n := SessionConfiguration{CSRFKeys: []session.CSRFKey{copyCSRF}}
	n.Native.Validation.LookupKeys = []session.DigestKey{older, copyLookup}
	if !sessionIssuerKeysMatch(n, p) {
		t.Fatal("independent immutable copies or rotation overlap rejected")
	}
	n.Native.Validation.LookupKeys[1] = wrongLookup
	if sessionIssuerKeysMatch(n, p) {
		t.Fatal("lookup version accepted different material")
	}
	n.Native.Validation.LookupKeys[1] = copyLookup
	n.CSRFKeys[0] = wrongCSRF
	if sessionIssuerKeysMatch(n, p) {
		t.Fatal("CSRF version accepted different material")
	}
	n.CSRFKeys = nil
	if !sessionIssuerKeysMatch(n, p) {
		t.Fatal("bearer-only composition required cookie keys")
	}
}
