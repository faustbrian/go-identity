package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestNativeCookieRevokeRejectsIncompleteProfile(t *testing.T) {
	if executor, err := NewCookieRevokeOneExecutor(nil, RevokeOneExecutorConfig{}, nil); executor != nil || err == nil {
		t.Fatal("incomplete strict composition accepted")
	}
	key, _ := session.NewCSRFKey(7, []byte("independent-test-csrf-material-32bytes"))
	for _, keys := range [][]session.CSRFKey{{{}}, {key, key}, {key, key, key, key, key}, {key}} {
		if e, err := NewCookieRevokeOneExecutor(nil, RevokeOneExecutorConfig{}, keys); e != nil || err == nil {
			t.Fatal("invalid strict configuration accepted")
		}
	}
	var executor *CookieRevokeOneExecutor
	for _, run := range []func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error){executor.ExecuteRevokeOne, executor.ExecuteRevokeOneWithCSRF} {
		if result, err := run(context.Background(), session.RevokeOneRequest{}); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("zero strict executor executed")
		}
	}
	if _, err := executor.RecoverRevokeOneCommand(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
		t.Fatal("zero strict recovery acquired history")
	}
}

func TestNativeCookieRevokeSelectsOnlyNamedEligibleKey(t *testing.T) {
	request, _, token, key := revokeCSRFRequestFixture(t, true)
	other, _ := session.NewCSRFKey(9, []byte("another-independent-test-key-material"))
	wrong, _ := session.NewCSRFKey(key.Version(), []byte("different-independent-test-material"))
	if selected, err := selectRevokeCSRFKey(request.Caller(), token, []session.CSRFKey{other, key}); err != nil || selected.Version() != key.Version() {
		t.Fatal("retained named key not selected", err)
	}
	for _, keys := range [][]session.CSRFKey{nil, {other}, {wrong, key}} {
		if _, err := selectRevokeCSRFKey(request.Caller(), token, keys); !errors.Is(err, session.ErrCSRFDenied) {
			t.Fatal("unknown/substituted key tried alternate material", err)
		}
	}
	if _, err := selectRevokeCSRFKey(session.Session{}, token, []session.CSRFKey{key}); !errors.Is(err, session.ErrCSRFDenied) {
		t.Fatal("absent state accepted", err)
	}
}

func TestNativeCookieRevokeConfigSnapshotAndRedaction(t *testing.T) {
	query := &kernel.CommandQueryPolicy{PolicyVersion: 1}
	admission := &kernel.CommandQueryPolicy{PolicyVersion: 2}
	final := &kernel.FinalAuthenticationConfig{Namespace: "original"}
	original := kernel.CoordinatorConfig{RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: query, AdmissionPolicy: admission, FinalAuthentication: final}
	copy := copyRevokeCoordinatorConfig(original)
	original.RetainedFingerprintKeys[1] = [32]byte{2}
	query.PolicyVersion, admission.PolicyVersion, final.Namespace = 3, 4, "changed"
	if copy.RetainedFingerprintKeys[1] != ([32]byte{1}) || copy.QueryPolicy.PolicyVersion != 1 || copy.AdmissionPolicy.PolicyVersion != 2 || copy.FinalAuthentication.Namespace != "original" {
		t.Fatal("caller-owned configuration remained mutable")
	}
	e := CookieRevokeOneExecutor{}
	if fmt.Sprintf("%+v", e) != "postgres.CookieRevokeOneExecutor(redacted)" {
		t.Fatal("runtime formatting not redacted")
	}
	if _, err := json.Marshal(e); err == nil {
		t.Fatal("runtime serialized")
	}
	if _, err := e.MarshalText(); err == nil {
		t.Fatal("runtime text serialized")
	}
}

func TestLegacyRevokeRejectsCSRFCustodyBeforeIO(t *testing.T) {
	request, service, _, _ := revokeCSRFRequestFixture(t, true)
	spec, _ := request.Caller().Bindings()
	legacy := &RevokeOneExecutor{owned: &IssueExecutor{clock: issueTestClock{now: spec.IssuedAt}}, sessions: service}
	result, err := legacy.ExecuteRevokeOne(context.Background(), request)
	if !errors.Is(err, session.ErrCSRFDenied) || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("legacy execution did not reject strict custody before primary IO", err)
	}
}
