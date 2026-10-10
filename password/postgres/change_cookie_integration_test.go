//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	session "github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// Plan: exercise an actual cookie commit, exact session continuation, original
// receipt/recovery after process reconstruction, eligible-key rotation and
// retirement, changed-token conflict and replay after source revocation. Keep
// the existing bearer ambiguity/portable tests; no fake terminal journal state.
// Returned next-request secret is owned/destroyed by the calling test.
func testCookiePasswordChangeCommit(t *testing.T, ctx context.Context, pool *database.Pool, source *passworddb.ReauthenticationService, sourceConfig passworddb.ReauthenticationConfig, policy passworddb.PasswordChangeConfig, config passworddb.KeyedPasswordChangeConfig, keys *keyring.Provider, request passworddb.PasswordChangeRequest, calls *atomic.Int64) (passworddb.PasswordChangeRequest, func()) {
	t.Helper()
	token, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{75}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(3, bytes.Repeat([]byte{76}, 32))
	if err != nil {
		t.Fatal(err)
	}
	binding := session.CSRFBinding{TenantID: request.TenantID, SessionID: request.Proof.SessionID, SessionVersion: request.Proof.SessionVersion}
	state, err := token.Digest(csrfKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	csrfSpec, err := state.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(csrfSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET record=jsonb_set(jsonb_set(record,'{Schema}',to_jsonb((record->>'Schema')::integer + CASE WHEN record ? 'CSRF' THEN 0 ELSE 1 END)),'{CSRF}',$2::jsonb) WHERE session_id=$1`, request.Proof.SessionID, wire); err != nil {
		t.Fatal("cookie synchronizer fixture failed", err)
	}
	repository, err := sessionpg.NewRepository(pool, sourceConfig.Session)
	if err != nil {
		t.Fatal(err)
	}
	beforeSession, err := repository.Get(ctx, request.TenantID, request.Proof.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	beforeSpec, err := beforeSession.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	policy.SessionDisposition, policy.MaximumSessions = sessionpg.PasswordChangePreserveSessions, 16
	base, err := passworddb.NewKeyedPasswordChangeService(source, policy, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := passworddb.NewCookieKeyedPasswordChangeService(base, []session.CSRFKey{csrfKey})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("password-cookie-committed"))
	if err != nil {
		t.Fatal(err)
	}
	input := passworddb.CookiePasswordChangeRequest{Request: request, IdempotencyKey: key, CSRFToken: token}
	before := calls.Load()
	result, err := cookie.Change(ctx, input)
	if err != nil || result.CommandID == "" || result.Outcome != identity.CommitOutcomeCommitted || result.CredentialVersion != 10 || !result.AuthorityInvalidated || calls.Load() != before+1 {
		t.Fatal("cookie password change did not commit exact successor", err)
	}
	afterSession, err := repository.Get(ctx, request.TenantID, request.Proof.SessionID)
	if err != nil || afterSession.Revoked || afterSession.Session.EffectiveCredentialVersion() != 10 {
		t.Fatal("cookie change lost preserved source", err)
	}
	afterSpec, err := afterSession.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	afterCSRF, err := afterSession.Session.CSRFState().Bindings()
	if err != nil || afterCSRF != csrfSpec || afterSpec.Authentication != beforeSpec.Authentication || afterSpec.IssuedAt != beforeSpec.IssuedAt || afterSpec.LastActivityAt != beforeSpec.LastActivityAt || afterSpec.Version != beforeSpec.Version || afterSpec.FamilyVersion != beforeSpec.FamilyVersion {
		t.Fatal("cookie change renewed original session custody", err)
	}
	var consumed bool
	var version string
	if err := pool.Raw().QueryRow(ctx, `SELECT p.consumed_command_id IS NOT NULL,c.version::text FROM identity_password.reauthentication_records p JOIN identity_password.credentials c USING(tenant_id,user_id) WHERE p.proof_id=$1`, string(request.Proof.Proof.ID)).Scan(&consumed, &version); err != nil || !consumed || version != "10" {
		t.Fatal("cookie commit lost atomic proof/password effects", err)
	}
	newKey, err := session.NewCSRFKey(4, bytes.Repeat([]byte{77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	query := identity.RecoveryQuery{CommandID: result.CommandID, TenantID: request.TenantID, UserID: identity.UserID(request.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.password.change", RecordID: "reauth-password"}
	replay := func() {
		t.Helper()
		before := calls.Load()
		// Construct a new native owner, not merely a wrapper over the first one.
		freshBase, err := passworddb.NewKeyedPasswordChangeService(source, policy, config, keys)
		if err != nil {
			t.Fatal(err)
		}
		retained, err := passworddb.NewCookieKeyedPasswordChangeService(freshBase, []session.CSRFKey{newKey, csrfKey})
		if err != nil {
			t.Fatal(err)
		}
		got, err := retained.Change(ctx, input)
		if err != nil || got != result || calls.Load() != before {
			t.Fatal("cookie retained-key restart changed original outcome", err)
		}
		recovered, err := retained.Recover(ctx, query, request.Caller)
		if err != nil || recovered != result || calls.Load() != before {
			t.Fatal("cookie code-free recovery changed original outcome", err)
		}
		retired, err := passworddb.NewCookieKeyedPasswordChangeService(freshBase, []session.CSRFKey{newKey})
		if err != nil {
			t.Fatal(err)
		}
		denied, err := retired.Change(ctx, input)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || denied.Outcome == identity.CommitOutcomeCommitted || denied.CredentialVersion != 0 || denied.AuthorityInvalidated || calls.Load() != before {
			t.Fatal("retired key disclosed committed cookie replay", err)
		}
		foreign, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{78}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		changed := input
		changed.CSRFToken = foreign
		conflicted, err := retained.Change(ctx, changed)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || conflicted.Outcome != identity.CommitOutcomeConflict || conflicted.CredentialVersion != 0 || calls.Load() != before {
			t.Fatal("changed CSRF token did not conflict before work", err)
		}
	}
	replay()
	verified, err := source.Verify(ctx, passworddb.ReauthenticationRequest{TenantID: request.TenantID, Session: request.Session, Password: request.Password, Caller: request.Caller, Network: request.Network, Device: "cookie-qualified-device", Target: passworddb.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.password.change", Audience: policy.Audience}})
	if err != nil || verified.Proof.Proof.ID == "" {
		t.Fatal("preserved cookie source could not verify successor password", err)
	}
	next, err := primitive.NewSecret([]byte("fourth-synthetic-test-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Destroy)
	request.Password, request.Proof = next, verified.Proof
	return request, replay
}
