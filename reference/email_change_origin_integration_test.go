//go:build integration

package reference_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestReferencePostgresEmailChangeOriginalCustody(t *testing.T) {
	for _, mode := range []string{"change-origin", "change-origin-graph"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: mode})
		})
	}
}

// Read the real committed request before any candidate link is delivered. The
// source cannot depend on a delivered proof, regenerate ciphertext, or grant
// replacement authority merely because a candidate exists.
func proveReferenceChangeOrigin(t *testing.T, ctx context.Context, f liveStores, service emailManagementConsumer, request passwordpg.EmailManagementRequest, old email.PreviousAddress) func() {
	t.Helper()
	source, ok := service.(email.ChangeOriginSource)
	if !ok {
		t.Fatal("native change owner has no code-independent original custody")
	}
	q := identity.RecoveryQuery{CommandID: request.Primary.CommandID, TenantID: request.Primary.TenantID, UserID: identity.UserID(request.Primary.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Primary.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.otp.email-change-request", RecordID: string(request.Primary.AddressID)}
	caller := request.Primary.Caller.Clone()
	caller.Request.Action = authorization.Action(q.OperationID)
	var before int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	original, err := source.ReadChangeOrigin(ctx, q, caller)
	if err != nil || original.OutputDigest == ([32]byte{}) || original.Spec.Binding.CommandID != q.CommandID || original.Spec.IdentifierID != request.Primary.AddressID || original.Spec.IdentifierVersion != 1 || original.Spec.VerificationVersion != 1 || original.Spec.Previous != old || original.FactorVersion == 0 || original.UserVersion == 0 || original.IdentifierAuthorityVersion == 0 {
		t.Fatal("original encrypted change custody not conserved", err)
	}
	commandID, err := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	if err != nil {
		t.Fatal("invalid fixture command")
	}
	var encrypted []byte
	if err := f.pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext FROM identity.commands WHERE tenant_id=$1 AND command_id=$2`, string(q.TenantID), commandID).Scan(&encrypted); err != nil || len(encrypted) < 100 {
		t.Fatal("original encrypted native custody absent", err)
	}
	defer clear(encrypted)
	if original.OutputDigest != sha256.Sum256(encrypted) {
		t.Fatal("origin digest does not bind exact retained ciphertext")
	}
	// Committed custody is immutable at the database boundary too. Keep that
	// control enabled rather than bypassing it to manufacture a corrupt origin.
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=set_byte(preparation_ciphertext,99,get_byte(preparation_ciphertext,99)#1) WHERE tenant_id=$1 AND command_id=$2`, string(q.TenantID), commandID); err == nil {
		t.Fatal("committed original encrypted custody was mutable")
	}
	retained, err := source.ReadChangeOrigin(ctx, q, caller)
	if err != nil || !reflect.DeepEqual(retained, original) {
		t.Fatal("rejected custody rewrite changed original provenance", err)
	}
	session, err := original.Session.Bindings()
	if err != nil || session.UserID != q.UserID || session.SessionID != original.Spec.SessionID || session.Version != original.Spec.SessionVersion || !original.Spec.ExpiresAt.After(original.Spec.IssuedAt) {
		t.Fatal("original change lost source session or validity", err)
	}
	for _, action := range []string{"identity.otp.email-change-request", "identity.otp.email-change-confirm", "identity.otp.email-change-confirm.recover"} {
		query, current := q, caller.Clone()
		query.OperationID, current.Request.Action = action, authorization.Action(action)
		again, err := source.ReadChangeOrigin(ctx, query, current)
		if err != nil || !reflect.DeepEqual(original, again) {
			t.Fatal("read renewed or retargeted original change custody", err)
		}
	}
	for _, mutate := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.CommandID, _ = identity.NewCommandID() },
		func(q *identity.RecoveryQuery) { q.RecordID = "another-pending-address" },
		func(q *identity.RecoveryQuery) { q.UserID = "another-user" },
		func(q *identity.RecoveryQuery) { q.TenantID = "another-tenant" },
		func(q *identity.RecoveryQuery) { q.ActorID = "another-actor" },
		func(q *identity.RecoveryQuery) { q.OperationID = "identity.otp.email-verify" },
	} {
		query := q
		mutate(&query)
		out, err := source.ReadChangeOrigin(ctx, query, caller)
		if err == nil || !reflect.DeepEqual(out, email.ChangeOrigin{}) {
			t.Fatal("foreign or noncommitted original disclosed change intent")
		}
	}
	denied := caller.Clone()
	denied.PolicyRevision++
	if out, err := source.ReadChangeOrigin(ctx, q, denied); err == nil || !reflect.DeepEqual(out, email.ChangeOrigin{}) {
		t.Fatal("historical request bypassed current disclosure policy")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if out, err := source.ReadChangeOrigin(canceled, q, caller); err == nil || !reflect.DeepEqual(out, email.ChangeOrigin{}) {
		t.Fatal("canceled source read disclosed change intent")
	}
	var after int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&after); err != nil || after != before {
		t.Fatal("original source read issued another delivery", err)
	}
	return func() {
		t.Helper()
		again, err := source.ReadChangeOrigin(ctx, q, caller)
		if err != nil || !reflect.DeepEqual(original, again) {
			t.Fatal("completed change lost historical code-free provenance", err)
		}
	}
}
