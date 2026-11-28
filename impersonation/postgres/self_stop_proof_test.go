package impersonationpostgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
)

func TestSelfStopSynchronizerBindsExactChild(t *testing.T) {
	key, err := session.NewCSRFKey(4, bytes.Repeat([]byte{29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	grant := impersonation.GrantID(id)
	token, spec, err := newStopProof("tenant-a", grant, key)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Binding.SessionID == string(grant) || spec.Binding.SessionVersion != 3 || spec.Binding.TenantID != "tenant-a" {
		t.Fatal("proof shares the ordinary session namespace or wrong active version")
	}
	stored, err := session.NewCSRFState(spec)
	if err != nil || stored.Check(spec.Binding, token, key) != nil {
		t.Fatal("original child synchronizer does not match digest custody", err)
	}
	wrong := spec.Binding
	wrong.TenantID = "tenant-b"
	if stored.Check(wrong, token, key) == nil {
		t.Fatal("same child synchronizer crossed tenant")
	}
	wrong = spec.Binding
	wrong.SessionID = string(grant)
	if stored.Check(wrong, token, key) == nil {
		t.Fatal("child synchronizer was accepted in ordinary session namespace")
	}
	otherID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := newStopProof("tenant-a", impersonation.GrantID(otherID), key)
	if err != nil || stored.Check(spec.Binding, other, key) == nil {
		t.Fatal("another grant in the same tenant supplied the stop proof", err)
	}
}
