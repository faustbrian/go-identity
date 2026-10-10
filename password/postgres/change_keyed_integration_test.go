//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// Plan: the real signed-proof/password/session transaction must have exactly one
// original keyed result across process reconstruction and a revoked source.
// Changed complete input must conflict before provider/hash/counter work. This
// is local real crypto/SQL, not HIBP interoperability or final release evidence.
func testNativeKeyedPasswordChange(t *testing.T, ctx context.Context, pool *database.Pool, source *passworddb.ReauthenticationService, sourceConfig passworddb.ReauthenticationConfig, policy passworddb.PasswordChangeConfig, request passworddb.PasswordChangeRequest, currentPassword primitive.Secret, calls *atomic.Int64) (passworddb.PasswordChangeResult, primitive.Secret) {
	t.Helper()
	base := kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	var history migrations.Source = kernel.RequestKeyMigrationSource{Base: base, Version: 13}
	history = kernel.RequestKeyPreparationMigrationSource{Base: history, Version: 14}
	history = kernel.PreparationMigrationSource{Base: history, Version: 15}
	history = kernel.AdmissionPreparationMigrationSource{Base: history, Version: 16}
	history = kernel.CounterPreparationMigrationSource{Base: history, Version: 17}
	items, err := history.Load(ctx)
	if err != nil {
		t.Fatal("keyed change migrations unavailable", err)
	}
	for _, item := range items {
		if item.Version() > 12 {
			if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
				t.Fatal("keyed change migration failed", err)
			}
		}
	}
	keys, err := keyring.New(map[string][]byte{"password-change": bytes.Repeat([]byte{61}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("password-change-test", [32]byte{62}, *sourceConfig.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config, err := passworddb.NewKeyedPasswordChangeConfig(requestKeys, [32]byte{63}, "password-change")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("cookie-original-state-fence", func(t *testing.T) {
		testCookiePasswordChangeFence(t, ctx, pool, source, sourceConfig, policy, config, keys, request, calls)
	})
	t.Run("keyed-original-signal-deadline", func(t *testing.T) {
		testKeyedPasswordSignalDeadline(t, ctx, pool, source, policy, config, keys, request, calls)
	})
	request, cookieReplay := testCookiePasswordChangeCommit(t, ctx, pool, source, sourceConfig, policy, config, keys, request, currentPassword, calls)
	// Preserve all original charges/snapshots while starting a fresh synthetic
	// window for the separately targeted bearer unknown-commit journey.
	if _, err := pool.Raw().Exec(ctx, `UPDATE password_risk.counter_windows SET started_at=started_at-interval '15 minutes',expires_at=expires_at-interval '15 minutes' WHERE tenant_id=$1 AND operation='identity.password.change'`, string(request.TenantID)); err != nil {
		t.Fatal("expired cookie risk-window fixture", err)
	}
	// Hold only the external provider seam, with no SQL transaction open, so a
	// second request demonstrably observes the original busy journal. The winner
	// loses its final COMMIT acknowledgement through the real wire fault boundary.
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enterOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	collect := policy.Screening.Collect
	policy.Screening.Timeout = 2 * time.Second
	policy.Screening.Collect = func(ctx context.Context, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		facts, err := collect(ctx, scope, candidate)
		enterOnce.Do(func() { close(entered) })
		select {
		case <-release:
			return facts, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	fault := &reauthenticationCommitFault{marker: []byte("UPDATE identity_password.reauthentication_records SET consumed_command_id")}
	faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
	if err != nil {
		t.Fatal("keyed fault pool unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if faultPool.Close(cleanup) != nil {
			t.Error("keyed fault pool cleanup failed")
		}
	}()
	faultSource, err := passworddb.NewReauthenticationService(faultPool, sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	service, err := passworddb.NewKeyedPasswordChangeService(faultSource, policy, config, keys)
	if err != nil {
		t.Fatal("keyed password change composition failed", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("password-change-original-1"))
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := passworddb.NewChangeWorkflow(service)
	if err != nil {
		t.Fatal("portable native workflow unavailable", err)
	}
	var port password.ChangeService = workflow
	caller := request.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(requestKeys.Policy.PolicyVersion)
	caller.Request.Tenant = authorization.TenantID(request.TenantID)
	caller.Request.Action = "identity.password.change"
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.password.change"}
	portable := password.ChangeRequest{TenantID: request.TenantID, Session: request.Session, Proof: request.Proof, Password: request.Password, Caller: caller, Network: request.Network, IdempotencyKey: key}
	before := calls.Load()
	type completion struct {
		result passworddb.PasswordChangeResult
		err    error
	}
	done := make(chan completion, 1)
	finished := make(chan struct{})
	workerCtx, stopWorker := context.WithCancel(ctx)
	go func() {
		defer close(finished)
		result, err := port.Change(workerCtx, portable)
		done <- completion{nativePortableResult(result), err}
	}()
	defer func() {
		releaseOnce.Do(func() { close(release) })
		stopWorker()
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		select {
		case <-finished:
		case <-cleanup.Done():
			t.Error("keyed test writer did not stop")
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original keyed admission did not enter")
	}
	var otherSecret primitive.Secret
	err = request.Password.Use(func(raw []byte) error {
		var err error
		otherSecret, err = primitive.NewSecret(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer otherSecret.Destroy()
	other := request
	other.Password = otherSecret
	busy, err := service.Change(ctx, other, key)
	if err != nil || busy.CommandID == "" || busy.Outcome != identity.CommitOutcomeInProgress || busy.CredentialVersion != 0 || calls.Load() != before+1 {
		t.Fatal("concurrent same-key submission repeated or replaced generation", err, busy.Outcome)
	}
	releaseOnce.Do(func() { close(release) })
	var original completion
	select {
	case original = <-done:
	case <-ctx.Done():
		t.Fatal("original keyed writer did not finish")
	}
	if original.err == nil || !fault.hit.Load() || original.result.CommandID != busy.CommandID || original.result.Outcome != identity.CommitOutcomeUnknown || original.result.CredentialVersion != 0 || original.result.AuthorityInvalidated {
		t.Fatal("keyed lost commit acknowledgement fabricated success", original.err, original.result.Outcome)
	}
	restarted, err := passworddb.NewKeyedPasswordChangeService(source, policy, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	query := identity.RecoveryQuery{CommandID: busy.CommandID, TenantID: request.TenantID, UserID: identity.UserID(request.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.password.change", RecordID: "reauth-password"}
	result, err := restarted.Recover(ctx, query, request.Caller)
	if err != nil || result.CommandID != busy.CommandID || result.Outcome != identity.CommitOutcomeCommitted || result.CredentialVersion != 11 || !result.AuthorityInvalidated || calls.Load() != before+1 {
		t.Fatal("keyed original outcome recovery failed", err, result.Outcome)
	}
	replay, err := restarted.Change(ctx, request, key)
	if err != nil || replay != result || calls.Load() != before+1 {
		t.Fatal("matching retry regenerated or lost original outcome", err)
	}
	restartedWorkflow, err := passworddb.NewChangeWorkflow(restarted)
	if err != nil {
		t.Fatal(err)
	}
	portableReplay, err := restartedWorkflow.Change(ctx, portable)
	if err != nil || nativePortableResult(portableReplay) != result || calls.Load() != before+1 {
		t.Fatal("portable restart changed original result", err)
	}
	portableRecovery, err := restartedWorkflow.Recover(ctx, query, request.Caller)
	if err != nil || portableRecovery != portableReplay || calls.Load() != before+1 {
		t.Fatal("portable code-free recovery changed original result", err)
	}
	keyless := portable
	keyless.IdempotencyKey = identity.IdempotencyKey{}
	keylessResult, err := restartedWorkflow.Change(ctx, keyless)
	if err == nil || keylessResult.CommandID != "" || keylessResult.Outcome != 0 || calls.Load() != before+1 {
		t.Fatal("portable keyless request fell back to native unkeyed command")
	}
	rotatedKeys, err := keyring.New(map[string][]byte{"password-change": bytes.Repeat([]byte{61}, 32), "password-change-next": bytes.Repeat([]byte{64}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	rotatedConfig := config
	rotatedConfig.ActiveEnvelopeKeyID = "password-change-next"
	rotated, err := passworddb.NewKeyedPasswordChangeService(source, policy, rotatedConfig, rotatedKeys)
	if err != nil {
		t.Fatal(err)
	}
	rotatedReplay, err := rotated.Change(ctx, request, key)
	if err != nil || rotatedReplay != result || calls.Load() != before+1 {
		t.Fatal("retained encryption-key rotation lost the original result", err)
	}
	missingOriginalKeys, err := keyring.New(map[string][]byte{"password-change-next": bytes.Repeat([]byte{64}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	missingOriginal, err := passworddb.NewKeyedPasswordChangeService(source, policy, rotatedConfig, missingOriginalKeys)
	if err != nil {
		t.Fatal(err)
	}
	missingReplay, err := missingOriginal.Change(ctx, request, key)
	if err == nil || missingReplay.CredentialVersion != 0 || missingReplay.AuthorityInvalidated || missingReplay.Outcome == identity.CommitOutcomeCommitted || calls.Load() != before+1 {
		t.Fatal("missing original decrypting key authorized replacement or repeated work")
	}
	changedPolicy := policy
	// The input's zero selects the resolved 100000 default, not a numeric cap.
	changedPolicy.MaximumSessions = 99999
	reconfigured, err := passworddb.NewKeyedPasswordChangeService(source, changedPolicy, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	reconfiguredReplay, err := reconfigured.Change(ctx, request, key)
	var policyConflict identity.ConflictError
	if !errors.As(err, &policyConflict) || reconfiguredReplay.Outcome != identity.CommitOutcomeConflict || reconfiguredReplay.CredentialVersion != 0 || calls.Load() != before+1 {
		t.Fatal("changed session policy reinterpreted the original keyed command", err)
	}
	var snapshots int
	rawID, _ := base64.RawURLEncoding.DecodeString(string(result.CommandID))
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM password_risk.counter_snapshots WHERE command_id=$1`, rawID).Scan(&snapshots); err != nil || snapshots != 4 {
		t.Fatal("keyed retry recharged protected counters", err)
	}
	for _, kind := range []string{"password", "proof", "network"} {
		t.Run("keyed-conflict-"+kind, func(t *testing.T) {
			changed := request
			switch kind {
			case "password":
				candidate, e := primitive.NewSecret([]byte("different-synthetic-password"))
				if e != nil {
					t.Fatal(e)
				}
				defer candidate.Destroy()
				changed.Password = candidate
			case "proof":
				changed.Proof.SessionVersion++
			case "network":
				changed.Network = "192.0.2.2"
			}
			out, e := restarted.Change(ctx, changed, key)
			var conflict identity.ConflictError
			if !errors.As(e, &conflict) || out.Outcome != identity.CommitOutcomeConflict || out.CredentialVersion != 0 || out.AuthorityInvalidated || calls.Load() != before+1 {
				t.Fatal("changed keyed intent did not conflict before work", kind, e)
			}
		})
	}
	// Bearer strict revoke-all has now revoked the original cookie source. Exact
	// committed replay still returns only its original receipt, never authority.
	cookieReplay()
	return result, request.Password
}

// Rotate the primary synchronizer after original admission but before mutation.
// A prechecked token must not survive the existing transaction's source fence.
func testCookiePasswordChangeFence(t *testing.T, ctx context.Context, pool *database.Pool, source *passworddb.ReauthenticationService, sourceConfig passworddb.ReauthenticationConfig, policy passworddb.PasswordChangeConfig, config passworddb.KeyedPasswordChangeConfig, keys *keyring.Provider, request passworddb.PasswordChangeRequest, calls *atomic.Int64) {
	t.Helper()
	var original []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM reauth_sessions.sessions WHERE session_id=$1`, request.Proof.SessionID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(cleanup, `UPDATE reauth_sessions.sessions SET record=$2::jsonb WHERE session_id=$1`, request.Proof.SessionID, original); err != nil {
			t.Error("cookie fixture cleanup failed", err)
		}
	}()
	token, _ := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{71}, 32)))
	foreign, _ := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{72}, 32)))
	csrfKey, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{73}, 32))
	binding := session.CSRFBinding{TenantID: request.TenantID, SessionID: request.Proof.SessionID, SessionVersion: request.Proof.SessionVersion}
	install := func(token session.CSRFToken) error {
		state, err := token.Digest(csrfKey, binding)
		if err != nil {
			return err
		}
		spec, err := state.Bindings()
		if err != nil {
			return err
		}
		wire, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		// Preserve existing continuation/OTP schema bits; adding the first
		// synchronizer advances the tokenless schema by one, not back to two.
		_, err = pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET record=jsonb_set(jsonb_set(record,'{Schema}',to_jsonb((record->>'Schema')::integer + CASE WHEN record ? 'CSRF' THEN 0 ELSE 1 END)),'{CSRF}',$2::jsonb) WHERE session_id=$1`, request.Proof.SessionID, wire)
		return err
	}
	if err := install(token); err != nil {
		t.Fatal(err)
	}
	collect := policy.Screening.Collect
	policy.Screening.Collect = func(ctx context.Context, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		facts, err := collect(ctx, scope, candidate)
		if err == nil {
			err = install(foreign)
		}
		return facts, err
	}
	base, err := passworddb.NewKeyedPasswordChangeService(source, policy, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := passworddb.NewCookieKeyedPasswordChangeService(base, []session.CSRFKey{csrfKey})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("password-cookie-fence"))
	before := calls.Load()
	for _, candidate := range []session.CSRFToken{{}, foreign} {
		out, err := cookie.Change(ctx, passworddb.CookiePasswordChangeRequest{Request: request, IdempotencyKey: key, CSRFToken: candidate})
		if err == nil || out.CredentialVersion != 0 || calls.Load() != before {
			t.Fatal("absent/foreign cookie token admitted work", err)
		}
	}
	out, err := cookie.Change(ctx, passworddb.CookiePasswordChangeRequest{Request: request, IdempotencyKey: key, CSRFToken: token})
	if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.CredentialVersion != 0 || calls.Load() != before+1 {
		t.Fatal("rotated token survived primary fence", err)
	}
	var consumed bool
	var version string
	if err := pool.Raw().QueryRow(ctx, `SELECT p.consumed_command_id IS NOT NULL,c.version::text FROM identity_password.reauthentication_records p JOIN identity_password.credentials c USING(tenant_id,user_id) WHERE p.proof_id=$1`, string(request.Proof.Proof.ID)).Scan(&consumed, &version); err != nil || consumed || version != "9" {
		t.Fatal("cookie fence leaked protected effects", err)
	}
	// The original prepared journal remains pending after the denied mutation.
	// Named-key eligibility must be checked before its early busy disclosure too;
	// current primary rotation cannot renew/rewrite original replay custody.
	retained, err := passworddb.NewCookieKeyedPasswordChangeService(base, []session.CSRFKey{csrfKey})
	if err != nil {
		t.Fatal(err)
	}
	replayRequest := passworddb.CookiePasswordChangeRequest{Request: request, IdempotencyKey: key, CSRFToken: token}
	replayed, err := retained.Change(ctx, replayRequest)
	if err != nil || replayed.Outcome != identity.CommitOutcomeInProgress || replayed.CommandID != out.CommandID || replayed.CredentialVersion != 0 || replayed.AuthorityInvalidated || calls.Load() != before+1 {
		t.Fatal("retained-key replay changed original pending journal", err)
	}
	newKey, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{74}, 32))
	retired, err := passworddb.NewCookieKeyedPasswordChangeService(base, []session.CSRFKey{newKey})
	if err != nil {
		t.Fatal(err)
	}
	denied, err := retired.Change(ctx, replayRequest)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || denied.CredentialVersion != 0 || denied.AuthorityInvalidated || calls.Load() != before+1 {
		t.Fatal("retired CSRF key disclosed original replay", err)
	}
}

func nativePortableResult(result password.ChangeResult) passworddb.PasswordChangeResult {
	return passworddb.PasswordChangeResult{CommandID: result.CommandID, Outcome: result.Outcome, CredentialVersion: result.CredentialVersion, AuthorityInvalidated: result.AuthorityInvalidated}
}

// A real outbox statement waits behind a task-owned advisory lock. Expiry must
// cancel the whole operation before that lock is released, not merely be checked
// before hashing. Original proof/material remain unchanged and the charge stays.
func testKeyedPasswordSignalDeadline(t *testing.T, ctx context.Context, pool *database.Pool, source *passworddb.ReauthenticationService, policy passworddb.PasswordChangeConfig, config passworddb.KeyedPasswordChangeConfig, keys *keyring.Provider, request passworddb.PasswordChangeRequest, calls *atomic.Int64) {
	t.Helper()
	locker, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = locker.Rollback(cleanup)
	}()
	if _, err := locker.Exec(ctx, `SELECT pg_advisory_xact_lock(88001)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION identity_password.wait_keyed_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(88001);RETURN NEW; END $$;CREATE TRIGGER wait_keyed_effect BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION identity_password.wait_keyed_effect()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := pool.Raw().Exec(cleanup, `DROP TRIGGER wait_keyed_effect ON public.identity_outbox_bindings;DROP FUNCTION identity_password.wait_keyed_effect()`); err != nil {
			t.Error("keyed deadline trigger cleanup failed", err)
		}
	}()
	entered := make(chan struct{})
	collect := policy.Screening.Collect
	policy.Screening.Collect = func(ctx context.Context, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		facts, err := collect(ctx, scope, candidate)
		facts = slices.Clone(facts)
		for i := range facts {
			if facts[i].Name == "status" {
				facts[i].ExpiresAt = scope.Now.Add(150 * time.Millisecond)
			}
		}
		close(entered)
		return facts, err
	}
	service, err := passworddb.NewKeyedPasswordChangeService(source, policy, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("password-change-short-signal"))
	if err != nil {
		t.Fatal(err)
	}
	type completion struct {
		result passworddb.PasswordChangeResult
		err    error
	}
	done, finished := make(chan completion, 1), make(chan struct{})
	workerCtx, stopWorker := context.WithCancel(ctx)
	before := calls.Load()
	go func() {
		defer close(finished)
		out, err := service.Change(workerCtx, request, key)
		done <- completion{out, err}
	}()
	defer func() {
		stopWorker()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		select {
		case <-finished:
		case <-cleanup.Done():
			t.Error("keyed deadline writer did not stop")
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("keyed signal collection did not start")
	}
	deadline := time.NewTimer(750 * time.Millisecond)
	defer deadline.Stop()
	var completionResult completion
	select {
	case completionResult = <-done:
	case <-deadline.C:
		t.Fatal("original signal expiry did not bound blocked SQL")
	case <-ctx.Done():
		t.Fatal("keyed deadline test expired")
	}
	out := completionResult.result
	if !errors.Is(completionResult.err, context.DeadlineExceeded) || out.CommandID == "" || out.Outcome == identity.CommitOutcomeCommitted || out.CredentialVersion != 0 || out.AuthorityInvalidated || calls.Load() != before+1 {
		t.Fatal("expired signal granted password mutation", completionResult.err, out.Outcome)
	}
	var consumed bool
	var version string
	if err := pool.Raw().QueryRow(ctx, `SELECT p.consumed_command_id IS NOT NULL,c.version::text FROM identity_password.reauthentication_records p JOIN identity_password.credentials c USING(tenant_id,user_id) WHERE p.proof_id=$1`, string(request.Proof.Proof.ID)).Scan(&consumed, &version); err != nil || consumed || version != "9" {
		t.Fatal("keyed deadline leaked proof or material effects", err)
	}
	rawID, _ := base64.RawURLEncoding.DecodeString(string(out.CommandID))
	var charged int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM password_risk.counter_snapshots WHERE command_id=$1`, rawID).Scan(&charged); err != nil || charged != 4 {
		t.Fatal("keyed deadline lost its original charge", err)
	}
}
