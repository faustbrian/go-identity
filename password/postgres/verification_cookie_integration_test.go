//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"reflect"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
)

// Reuse the real kernel/session/password/audit/outbox fixture; only the external
// abuse counter boundary supplies a callback for deterministic invalidation.
func testCookieVerificationNative(t *testing.T, ctx context.Context, pool *database.Pool, config passworddb.ReauthenticationConfig, base *passworddb.ReauthenticationService, request passworddb.ReauthenticationRequest, caller authorization.DecisionContext) {
	t.Helper()
	var original []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM reauth_sessions.sessions WHERE session_id='reauth-session'`).Scan(&original); err != nil {
		t.Fatal("source record unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := pool.Raw().Exec(cleanup, `UPDATE reauth_sessions.sessions SET record=$1::jsonb,state='active'`, original); err != nil {
			t.Error("source restoration failed")
		}
		if _, err := pool.Raw().Exec(cleanup, `UPDATE reauth_sessions.families SET state='active',version=1`); err != nil {
			t.Error("family restoration failed")
		}
	})
	key, _ := session.NewCSRFKey(3, bytes.Repeat([]byte{81}, 32))
	newKey, _ := session.NewCSRFKey(4, bytes.Repeat([]byte{82}, 32))
	token, _ := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{83}, 32)))
	wrong, _ := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{84}, 32)))
	bound := session.CSRFBinding{TenantID: request.TenantID, SessionID: "reauth-session", SessionVersion: 1}
	state, err := token.Digest(key, bound)
	if err != nil {
		t.Fatal(err)
	}
	stateSpec, _ := state.Bindings()
	wire, _ := json.Marshal(stateSpec)
	install := func() {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET record=jsonb_set(jsonb_set($1::jsonb,'{Schema}','2'::jsonb),'{CSRF}',$2::jsonb),state='active'`, original, wire); err != nil {
			t.Fatal("CSRF fixture failed")
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.families SET state='active',version=1`); err != nil {
			t.Fatal("family fixture failed")
		}
	}
	install()
	keys := []session.CSRFKey{newKey, key}
	cookie, err := passworddb.NewCookieVerificationWorkflow(base, keys)
	if err != nil {
		t.Fatal(err)
	}
	// Caller-owned startup slices cannot retire the frozen eligible key.
	keys[1] = newKey
	input := password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: request.TenantID, Session: request.Session, Password: request.Password, Target: password.VerificationTarget{Purpose: request.Target.Purpose, Action: request.Target.Action, Audience: request.Target.Audience}, Caller: caller, Network: request.Network, Device: request.Device}, CSRFToken: token}
	effects := func(command identity.CommandID) (int, int, int) {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(string(command))
		var records, audits, events int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&records, &audits, &events); err != nil {
			t.Fatal("effect read failed")
		}
		return records, audits, events
	}
	assertDenied := func(w password.CookieVerificationService, r password.CookieVerificationRequest) {
		t.Helper()
		got, err := w.Verify(ctx, r)
		if err == nil || got.Proof != (auth.ReauthenticationProof{}) || got.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("cookie denial delivered authority", err, got.Outcome)
		}
		// A known abort may retain its required failure audit, not success effects.
		if records, _, events := effects(got.CommandID); records != 0 || events != 0 {
			t.Fatal("cookie denial committed protected effects")
		}
	}
	for _, kind := range []string{"missing", "wrong", "retired", "foreign-binding", "absent-state"} {
		t.Run(kind, func(t *testing.T) {
			install()
			r, w := input, password.CookieVerificationService(cookie)
			switch kind {
			case "missing":
				r.CSRFToken = session.CSRFToken{}
			case "wrong":
				r.CSRFToken = wrong
			case "retired":
				w, err = passworddb.NewCookieVerificationWorkflow(base, []session.CSRFKey{newKey})
				if err != nil {
					t.Fatal(err)
				}
			case "foreign-binding":
				foreign := bound
				foreign.TenantID = "foreign"
				foreignState, _ := token.Digest(key, foreign)
				spec, _ := foreignState.Bindings()
				// A digest made for another tenant cannot authenticate this
				// structurally valid session binding.
				spec.Binding = bound
				b, _ := json.Marshal(spec)
				if _, err := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET record=jsonb_set(record,'{CSRF}',$1::jsonb)`, b); err != nil {
					t.Fatal(err)
				}
			case "absent-state":
				if _, err := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET record=$1::jsonb`, original); err != nil {
					t.Fatal(err)
				}
			}
			assertDenied(w, r)
		})
	}
	t.Run("wrong-named-key-material", func(t *testing.T) {
		install()
		badKey, _ := session.NewCSRFKey(3, bytes.Repeat([]byte{85}, 32))
		w, e := passworddb.NewCookieVerificationWorkflow(base, []session.CSRFKey{badKey, newKey})
		if e != nil {
			t.Fatal(e)
		}
		assertDenied(w, input)
	})
	install()
	repo, _ := sessionpg.NewRepository(pool, config.Session)
	before, err := repo.Get(ctx, request.TenantID, "reauth-session")
	if err != nil {
		t.Fatal(err)
	}
	got, err := cookie.Verify(ctx, input)
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Proof.SessionID != bound.SessionID || got.Proof.SessionVersion != bound.SessionVersion {
		t.Fatal("valid cookie verification failed", err, got.Outcome)
	}
	if a, b, c := effects(got.CommandID); a != 1 || b != 1 || c != 1 {
		t.Fatal("cookie effects not atomic")
	}
	passwords, _ := passworddb.NewRepository(pool, config.Repository)
	record, err := passwords.Reauthentication(ctx, got.Proof.Proof.ID)
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := record.SigningBytes()
	if !ed25519.Verify(config.VerificationKeys[record.KeyID], frame, record.Signature) || record.Proof != got.Proof {
		t.Fatal("cookie proof is not signed original")
	}
	after, err := repo.Get(ctx, request.TenantID, "reauth-session")
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := sessionpg.OriginalSessionFields(before.Session)
	afterFields, _ := sessionpg.OriginalSessionFields(after.Session)
	if !reflect.DeepEqual(fields, afterFields) {
		t.Fatal("verification changed session or synchronizer")
	}
	query := identity.RecoveryQuery{CommandID: got.CommandID, TenantID: request.TenantID, UserID: identity.UserID(caller.Request.Subject.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.password.verify", RecordID: string(got.CommandID)}
	history, err := cookie.Recover(ctx, query, caller)
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Proof != (auth.ReauthenticationProof{}) {
		t.Fatal("cookie recovery redelivered proof", err)
	}
	t.Run("concurrent-same-synchronizer", func(t *testing.T) {
		var wg sync.WaitGroup
		var results [2]password.VerificationResult
		var failures [2]error
		for i := range results {
			secret, e := primitive.NewSecret([]byte("synthetic-test-password"))
			if e != nil {
				t.Fatal(e)
			}
			r := input
			r.Request.Password = secret
			wg.Go(func() { defer secret.Destroy(); results[i], failures[i] = cookie.Verify(ctx, r) })
		}
		wg.Wait()
		for i, r := range results {
			if failures[i] != nil || r.Outcome != identity.CommitOutcomeCommitted || r.Proof == (auth.ReauthenticationProof{}) {
				t.Fatal("shared synchronizer was consumed", failures[i])
			}
			if a, b, c := effects(r.CommandID); a != 1 || b != 1 || c != 1 {
				t.Fatal("concurrent proof effects incomplete")
			}
		}
		if results[0].CommandID == results[1].CommandID || results[0].Proof.Proof.ID == results[1].Proof.Proof.ID {
			t.Fatal("non-keyed invocations reused proof")
		}
	})
	for _, kind := range []string{"rotate-without-version", "revoke-session", "revoke-family"} {
		t.Run(kind, func(t *testing.T) {
			install()
			var hit bool
			fixture := &reauthenticationRiskFixture{onCharge: func() {
				hit = true
				var sql string
				var arg []byte
				switch kind {
				case "rotate-without-version":
					replacement, _ := wrong.Digest(key, bound)
					spec, _ := replacement.Bindings()
					arg, _ = json.Marshal(spec)
					sql = `UPDATE reauth_sessions.sessions SET record=jsonb_set(record,'{CSRF}',$1::jsonb)`
				case "revoke-session":
					sql = `UPDATE reauth_sessions.sessions SET state='revoked'`
				case "revoke-family":
					sql = `UPDATE reauth_sessions.families SET state='revoked'`
				}
				var e error
				if arg != nil {
					_, e = pool.Raw().Exec(ctx, sql, arg)
				} else {
					_, e = pool.Raw().Exec(ctx, sql)
				}
				if e != nil {
					t.Error("race fixture failed")
				}
			}}
			c := config
			c.Risk = reauthenticationRisk(t, fixture)
			native, e := passworddb.NewReauthenticationService(pool, c)
			if e != nil {
				t.Fatal(e)
			}
			protected, e := passworddb.NewCookieVerificationWorkflow(native, []session.CSRFKey{key})
			if e != nil {
				t.Fatal(e)
			}
			assertDenied(protected, input)
			if !hit {
				t.Fatal("race did not occur after lookup")
			}
		})
	}
	install()
	t.Run("bounded-session-lock", func(t *testing.T) {
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		}()
		if _, e = tx.Exec(ctx, `UPDATE reauth_sessions.sessions SET state=state`); e != nil {
			t.Fatal(e)
		}
		bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		defer stop()
		out, e := cookie.Verify(bounded, input)
		if !errors.Is(e, context.DeadlineExceeded) || out.Proof != (auth.ReauthenticationProof{}) || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("blocked cookie fence lost deadline", e)
		}
		if e = tx.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		out, e = cookie.Verify(ctx, input)
		if e != nil || out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("cookie fence leaked after timeout", e)
		}
	})
	for _, table := range []string{"audit.identity_command_bindings", "public.identity_outbox_bindings"} {
		t.Run("cookie-rollback-"+table, func(t *testing.T) {
			if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION identity_password.reject_cookie_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic effect failure'; END $$; CREATE TRIGGER reject_cookie_effect BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION identity_password.reject_cookie_effect()`); e != nil {
				t.Fatal("effect fault unavailable")
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if _, e := pool.Raw().Exec(cleanup, `DROP TRIGGER reject_cookie_effect ON `+table+`;DROP FUNCTION identity_password.reject_cookie_effect()`); e != nil {
					t.Error("effect fault cleanup failed")
				}
			})
			out, e := cookie.Verify(ctx, input)
			want := identity.CommitOutcomeNotCommitted
			if table == "audit.identity_command_bindings" {
				want = identity.CommitOutcomeUnknown
			}
			if e == nil || out.Outcome != want || out.Proof != (auth.ReauthenticationProof{}) {
				t.Fatal("cookie failure fabricated commit", e, out.Outcome)
			}
			if a, _, c := effects(out.CommandID); a != 0 || c != 0 {
				t.Fatal("cookie rollback left protected effects")
			}
		})
	}
	for _, beforeCommit := range []bool{true, false} {
		name := "cookie-disconnect-after-commit"
		if beforeCommit {
			name = "cookie-disconnect-before-commit"
		}
		t.Run(name, func(t *testing.T) {
			fault := &reauthenticationCommitFault{before: beforeCommit}
			faultPool, e := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
			if e != nil {
				t.Fatal("fault pool unavailable")
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if e := faultPool.Close(cleanup); e != nil {
					t.Error("fault pool cleanup failed")
				}
			})
			c := config
			c.Coordinator.LeaseDuration = 500 * time.Millisecond
			native, e := passworddb.NewReauthenticationService(faultPool, c)
			if e != nil {
				t.Fatal(e)
			}
			w, e := passworddb.NewCookieVerificationWorkflow(native, []session.CSRFKey{key})
			if e != nil {
				t.Fatal(e)
			}
			out, e := w.Verify(ctx, input)
			if e == nil || !fault.hit.Load() || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID == "" || out.Proof != (auth.ReauthenticationProof{}) {
				t.Fatal("cookie disconnect fabricated authority", e, out.Outcome)
			}
			want, outcome := 1, identity.CommitOutcomeCommitted
			if beforeCommit {
				want, outcome = 0, identity.CommitOutcomeNotCommitted
			}
			if a, b, d := effects(out.CommandID); a != want || b != want || d != want {
				t.Fatal("cookie disconnect lost all-or-none effects")
			}
			fresh, e := passworddb.NewReauthenticationService(pool, c)
			if e != nil {
				t.Fatal(e)
			}
			restarted, e := passworddb.NewCookieVerificationWorkflow(fresh, []session.CSRFKey{newKey})
			if e != nil {
				t.Fatal(e)
			}
			q := query
			q.CommandID = out.CommandID
			q.RecordID = string(out.CommandID)
			bounded, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				history, e := restarted.Recover(bounded, q, caller)
				if history.Proof != (auth.ReauthenticationProof{}) {
					t.Fatal("restart recovery redelivered proof")
				}
				if history.Outcome == outcome {
					if !beforeCommit && e != nil {
						t.Fatal("committed history denied", e)
					}
					break
				}
				select {
				case <-bounded.Done():
					t.Fatal("cookie outcome unresolved", history.Outcome)
				case <-ticker.C:
				}
			}
			foreign := q
			foreign.TenantID = "foreign"
			if out, e := restarted.Recover(ctx, foreign, caller); e == nil || out != (password.VerificationResult{}) {
				t.Fatal("foreign cookie history disclosed")
			}
		})
	}
	t.Run("protected-fence-precedes-invalidation", func(t *testing.T) {
		blocker, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = blocker.Rollback(cleanup)
		}()
		if _, e = blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(81123019)`); e != nil {
			t.Fatal("proof barrier unavailable")
		}
		if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION identity_password.block_cookie_proof() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(81123019); RETURN NEW; END $$;CREATE TRIGGER block_cookie_proof BEFORE INSERT ON identity_password.reauthentication_records FOR EACH ROW EXECUTE FUNCTION identity_password.block_cookie_proof()`); e != nil {
			t.Fatal("proof barrier trigger unavailable")
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if _, e := pool.Raw().Exec(cleanup, `DROP TRIGGER block_cookie_proof ON identity_password.reauthentication_records;DROP FUNCTION identity_password.block_cookie_proof()`); e != nil {
				t.Error("proof barrier cleanup failed")
			}
		})
		var out password.VerificationResult
		var failure error
		done := make(chan struct{})
		go func() { defer close(done); out, failure = cookie.Verify(ctx, input) }()
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = blocker.Rollback(cleanup)
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("verification did not drain")
			}
		}()
		wait, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			var waiting bool
			if e := pool.Raw().QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')`).Scan(&waiting); e != nil {
				t.Fatal("barrier observation failed")
			}
			if waiting {
				break
			}
			select {
			case <-wait.Done():
				t.Fatal("proof did not enter barrier")
			case <-ticker.C:
			}
		}
		mutator, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = mutator.Rollback(cleanup)
		}()
		if _, e = mutator.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); e != nil {
			t.Fatal(e)
		}
		_, e = mutator.Exec(ctx, `UPDATE reauth_sessions.sessions SET state='revoked'`)
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "55P03" {
			_ = mutator.Rollback(ctx)
			t.Fatal("invalidation bypassed protected session fence")
		}
		if e = mutator.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		if e = blocker.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("proof did not finish")
		}
		if failure != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Proof == (auth.ReauthenticationProof{}) {
			t.Fatal("earlier proof could not commit", failure)
		}
		if _, e = pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET state='revoked'`); e != nil {
			t.Fatal("later invalidation failed")
		}
		assertDenied(cookie, input)
		install()
	})
	var consumed bool
	if e := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(got.Proof.Proof.ID)).Scan(&consumed); e != nil || consumed {
		t.Fatal("verification consumed original proof")
	}
	if value, e := token.Reveal(); e != nil || value != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{83}, 32)) {
		t.Fatal("native verification consumed synchronizer custody")
	}
}
