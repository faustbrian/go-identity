//go:build integration

package passwordintegration_test

import (
	"context"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// This checks restoration of actual native-issued signed custody and exact
// borrowed synchronizer. It does NOT prove live URI admission or revelation.
func testURIPrimaryRestoration(t *testing.T, ctx context.Context, base *passworddb.MFAEnablePrimarySource, enable passworddb.MFAEnablePrimaryRequest, snapshot []byte, csrf session.CSRFToken, key session.CSRFKey, caller authorization.DecisionContext) {
	t.Helper()
	command, _ := identity.NewCommandID()
	caller = caller.Clone()
	caller.Request.Action = "identity.mfa.totp-uri"
	r := mfa.TotpUriRequest{TenantID: enable.TenantID, EnrollmentID: mfa.EnrollmentID(enable.FactorID), CommandID: command, Session: enable.Session, CSRFToken: csrf, Caller: caller, Origin: "https://app.test", Network: "127.0.0.1"}
	if restored, err := base.RestoreEnrollmentForURI(ctx, r, enable.CommandID, 1, snapshot); err == nil || restored != nil {
		t.Fatal("bearer-only source restored URI disclosure custody")
	}
	source, err := passworddb.NewCookieMFAEnablePrimarySource(base, []session.CSRFKey{key})
	if err != nil {
		t.Fatal("retained URI synchronizer selection rejected")
	}
	for _, keys := range [][]session.CSRFKey{nil, {{}}, {key, key}, {key, key, key, key, key}} {
		if configured, err := passworddb.NewCookieMFAEnablePrimarySource(base, keys); err == nil || configured != nil {
			t.Fatal("configured base admitted invalid synchronizer selection")
		}
	}
	port, err := source.RestoreEnrollmentForURI(ctx, r, enable.CommandID, 1, snapshot)
	if err != nil || port == nil {
		t.Fatal("exact original source session and synchronizer denied")
	}
	b := identity.CommandBinding{CommandID: command, TenantID: enable.TenantID, UserID: identity.UserID(caller.Request.Subject.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, RecordID: enable.FactorID, OperationID: "identity.mfa.totp-uri", SchemaID: "mfa-totp-uri", SchemaVersion: 1, PolicyID: "identity-mfa", PolicyVersion: 9, CorrelationID: string(command)}
	c, err := port.Command(b, nil)
	if err != nil {
		t.Fatal("URI custody failed to bind the separate command")
	}
	if native, ok := port.(passworddb.MFAEnableAdmission); !ok || native.Consume(ctx, kernel.Work{}, nil, c) == nil {
		t.Fatal("URI custody permitted a second proof consumption")
	}
	if port.Admit(ctx, kernel.Work{}, nil, c) == nil {
		t.Fatal("restoration alone granted mutation without registered native Work")
	}
	code, _ := auth.NewOneTimeCode("123456")
	confirmCaller := caller.Clone()
	confirmCaller.Request.Action = "identity.mfa.totp-verify"
	confirm := mfa.TotpVerifyRequest{TenantID: enable.TenantID, CommandID: command, FactorID: mfa.FactorID(enable.FactorID), Code: code, Origin: r.Origin, Network: r.Network, Caller: confirmCaller, Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: enable.Session, CSRFToken: csrf}}
	confirmation, err := source.RestoreEnrollmentForConfirmation(ctx, confirm, enable.CommandID, 2, snapshot)
	if err != nil || confirmation == nil {
		t.Fatal("exact original primary/synchronizer confirmation custody denied")
	}
	if _, err := confirmation.Command(b, nil); err == nil {
		t.Fatal("confirmation custody accepted URI command profile")
	}
	confirmBinding := b
	confirmBinding.OperationID = "identity.mfa.totp-verify"
	confirmBinding.SchemaID = "mfa-totp-enrollment-confirm"
	confirmCommand, err := confirmation.Command(confirmBinding, nil)
	if err != nil {
		t.Fatal("confirmation command failed to preserve original custody")
	}
	if native, ok := confirmation.(passworddb.MFAEnableAdmission); !ok || native.Consume(ctx, kernel.Work{}, nil, confirmCommand) == nil {
		t.Fatal("confirmation consumed original enable proof twice")
	}
	original, err := port.Original()
	originalBinding, bindingErr := original.Bindings()
	if err != nil || bindingErr != nil || originalBinding.SessionID != enable.Proof.SessionID || originalBinding.Version != enable.Proof.SessionVersion {
		t.Fatal("URI restoration changed original source session")
	}
	wrongCSRF, _ := session.NewCSRFToken()
	for _, change := range []func(*mfa.TotpUriRequest){
		func(r *mfa.TotpUriRequest) { r.CSRFToken = wrongCSRF },
		func(r *mfa.TotpUriRequest) {
			r.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		},
		func(r *mfa.TotpUriRequest) { r.CommandID = enable.CommandID },
		func(r *mfa.TotpUriRequest) {
			r.Caller.Request.Subject.ID = "foreign"
			r.Caller.Request.Resource.ID = "foreign"
		},
	} {
		candidate := r
		candidate.Caller = r.Caller.Clone()
		change(&candidate)
		if custody, err := source.RestoreEnrollmentForURI(ctx, candidate, enable.CommandID, 1, snapshot); err == nil || custody != nil {
			t.Fatal("substituted URI custody admitted")
		}
	}
	retiredKey, _ := session.NewCSRFKey(key.Version()+1, make([]byte, 32))
	retired, err := passworddb.NewCookieMFAEnablePrimarySource(base, []session.CSRFKey{retiredKey})
	if err != nil {
		t.Fatal(err)
	}
	if custody, err := retired.RestoreEnrollmentForURI(ctx, r, enable.CommandID, 1, snapshot); err == nil || custody != nil {
		t.Fatal("URI disclosure fell back after synchronizer retirement")
	}
	if _, err := r.CSRFToken.Reveal(); err != nil {
		t.Fatal("restoration consumed borrowed token delivery permission")
	}
}
