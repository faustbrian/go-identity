//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

func testPublicResetRequest(t *testing.T, ctx context.Context, previous *ResetService, keys *keyring.Provider, mail resetRequestDeliveryPreparation, canonical string, signin *SigninService, signinConfig SigninConfig) {
	t.Helper()
	var installed bool
	if err := previous.pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.request_key_mappings') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		history, err := (kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 30}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if m.Version() == 30 {
				if _, err := previous.pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	normalization, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "reset-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	address, _ := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization})
	c := previous.config()
	collect := c.Screening.Collect
	c.Screening.Collect = nil
	c.CollectReset = func(ctx context.Context, binding identity.CommandBinding, challenge string, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		if scope.Attempt != string(binding.CommandID) || scope.Tenant != string(binding.TenantID) || scope.Operation != risk.Action(binding.OperationID) || binding.CorrelationID != string(binding.CommandID) || binding.PolicyID != c.PolicyID || binding.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || binding.ActorID != signinTestActor || binding.ActorKind != authorization.SubjectServiceAccount {
			t.Fatal("public reset screening lost original attribution")
		}
		var original bool
		if err := previous.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM capability_identity_one_use WHERE capability_id=$1 AND tenant_id=$2 AND subject_id=$3 AND origin_command_id IS NOT NULL)`, challenge, string(binding.TenantID), string(binding.UserID)).Scan(&original); err != nil || !original {
			t.Fatal("public reset screening fabricated challenge identity", err)
		}
		return collect(ctx, scope, candidate)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("public-reset", [32]byte{108}, *c.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	c.Request = &ResetRequestConfig{Address: address, RequestKeys: requestKeys, Lifetime: time.Minute, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "reset-mail", ActiveEnvelopeKey: "reset-issuer", EnvelopeKeys: map[string][]byte{"reset-issuer": bytes.Repeat([]byte{104}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "public-reset", HMAC: bytes.Repeat([]byte{93}, 32)}}, Clock: time.Now}, Delivery: SignupDeliveryConfig{Owner: mail.owner, Renderer: mail.renderer, Resolver: mail.resolver, Endpoint: mail.endpoint, TemplateID: mail.template, TemplateVersion: mail.templateVersion, ProviderVersion: mail.providerVersion, Locales: mail.locales, ScopeKey: mail.scopeKey, Timeout: mail.timeout}}
	service, err := NewResetService(previous.pool, c, keys)
	if err != nil {
		t.Fatal("public reset request composition", err)
	}
	t.Run("passkey removal recovery owner", func(t *testing.T) {
		testPasskeyRemovalRecoveryOwner(t, ctx, service, canonical)
	})
	var public password.ResetService = service
	id, _ := identity.NewCommandID()
	key, _ := identity.NewIdempotencyKey([]byte("synthetic-public-reset-request-001"))
	caller := authorization.DecisionContext{PolicyRevision: 3, CorrelationID: string(id), Request: authorization.Request{Tenant: signinTestTenant, Action: authorization.Action(resetRequestOperation().OperationID), Subject: authorization.Subject{ID: signinTestActor, Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(resetRequestOperation().OperationID)}}}
	r := password.ResetRequestRequest{TenantID: signinTestTenant, CommandID: id, Identifier: identifier.Input(canonical), CallbackURL: "https://identity.test/reset", IdempotencyKey: key, Caller: caller, Origin: "https://identity.test", Network: "192.0.2.1", Device: "synthetic-device"}
	httpFixture, r := newResetHTTPFixture(t, ctx, service, r)
	// Both calls begin against an unreserved original request. Independent
	// transport correlation must not create competing issuance identities.
	type observation struct {
		result password.ResetRequestResult
		err    error
	}
	start := make(chan struct{})
	observed := make(chan observation, 2)
	var attempts [2]password.ResetRequestRequest
	for i := range attempts {
		correlation, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		attempts[i] = r
		attempts[i].Caller = r.Caller.Clone()
		attempts[i].Caller.CorrelationID = string(correlation)
	}
	for _, attempt := range attempts {
		go func() {
			<-start
			result, err := public.ResetRequest(ctx, attempt)
			observed <- observation{result, err}
		}()
	}
	close(start)
	var concurrent [2]observation
	for i := range concurrent {
		concurrent[i] = <-observed
	}
	accepted := httpFixture.request(r)
	if accepted.Validate() != nil || !accepted.Accepted {
		t.Fatal("public reset request returned invalid acknowledgement")
	}
	committed := 0
	for _, call := range concurrent {
		if call.result.CommandID != accepted.CommandID {
			t.Fatal("concurrent original request changed command identity")
		}
		if call.err == nil && call.result.Outcome == identity.CommitOutcomeCommitted {
			committed++
			if call.result != accepted {
				t.Fatal("concurrent original request changed acknowledgement")
			}
		} else if call.result.Validate() != nil || call.result.Accepted || call.result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("concurrent identical request failed outside bounded busy outcome", call.err)
		}
	}
	if committed == 0 {
		t.Fatal("concurrent original request had no committed winner")
	}
	if again, e := public.ResetRequest(ctx, r); e != nil || again != accepted {
		t.Fatal("public reset request retry changed acknowledgement", e)
	}
	commandBytes, _ := base64.RawURLEncoding.DecodeString(string(accepted.CommandID))
	var messages, grants int
	if e := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, commandBytes, string(accepted.CommandID)).Scan(&messages, &grants); e != nil || messages != 1 || grants != 1 {
		t.Fatal("public request replay duplicated or omitted issuer/delivery effects", e)
	}
	changed := r
	changed.Identifier = "foreign@example.test"
	var conflict identity.ConflictError
	if _, e := public.ResetRequest(ctx, changed); !errors.As(e, &conflict) {
		t.Fatal("changed reset request reused original key", e)
	}
	q := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: accepted.CommandID, AnonymousFlowID: string(id), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: resetRequestOperation().OperationID}
	if recovered, e := public.RecoverResetRequest(ctx, q, caller); e != nil || recovered != accepted {
		t.Fatal("proof-free original request recovery", e)
	}
	foreignQuery := q
	foreignID, _ := identity.NewCommandID()
	foreignQuery.AnonymousFlowID = string(foreignID)
	var forbidden identity.ForbiddenError
	if _, e := public.RecoverResetRequest(ctx, foreignQuery, caller); !errors.As(e, &forbidden) {
		t.Fatal("foreign flow disclosed original request", e)
	}
	foreignCallback := r
	foreignCallback.CallbackURL = "https://foreign.test/reset"
	if _, e := public.ResetRequest(ctx, foreignCallback); !errors.As(e, &forbidden) {
		t.Fatal("unselected reset callback admitted", e)
	}
	mailKeys, _ := keyring.New(map[string][]byte{"reset-mail": bytes.Repeat([]byte{102}, 32)})
	mailCrypto, _ := envelope.NewService(mailKeys)
	proof := captureResetDelivery(t, ctx, service.pool, mail, c.Coordinator, canonical, mailCrypto)
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	secret, _ := primitive.NewSecret([]byte("synthetic-full-public-reset"))
	defer secret.Destroy()
	completion, _ := identity.NewCommandID()
	cCaller := caller.Clone()
	cCaller.Request.Action = authorization.Action(resetOperation().OperationID)
	cCaller.Request.Resource = authorization.Resource{Type: "identity.user"}
	cCaller.CorrelationID = string(completion)
	user, credential, challenge, lifetime, sourceErr := service.ResetCompletionRateSource(ctx, proof, cCaller)
	if sourceErr != nil || user == "" || credential == "" || challenge == "" || lifetime != c.Request.Lifetime {
		t.Fatal("native reset issued challenge source", sourceErr)
	}
	foreignSource := cCaller.Clone()
	foreignSource.Request.Tenant = "foreign-tenant"
	if u, c, g, l, e := service.ResetCompletionRateSource(ctx, proof, foreignSource); e == nil || u != "" || c != "" || g != "" || l != 0 {
		t.Fatal("foreign tenant disclosed reset challenge")
	}
	foreignSource = cCaller.Clone()
	foreignSource.PolicyRevision++
	if u, c, g, l, e := service.ResetCompletionRateSource(ctx, proof, foreignSource); e == nil || u != "" || c != "" || g != "" || l != 0 {
		t.Fatal("stale policy disclosed reset challenge")
	}
	completed := httpFixture.complete(password.ResetCompleteRequest{TenantID: r.TenantID, CommandID: completion, Token: proof, NewPassword: secret, Caller: cCaller, Origin: r.Origin, Network: r.Network, Device: r.Device})
	if completed.Outcome != identity.CommitOutcomeCommitted || !completed.SessionsRevoked {
		t.Fatal("public request delivered proof cannot complete reset")
	}
	var active int
	if e := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{c.Session.Schema, "sessions"}.Sanitize()+` WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND canonical_value=$2) AND state='active'`, signinTestTenant, canonical).Scan(&active); e != nil || active != 0 {
		t.Fatal("public request/completion retained a live predecessor session", e)
	}
	if login, e := resetTestSignin(t, ctx, service.pool, signin, signinConfig, canonical, []byte("synthetic-public-reset-password")); e != nil || login.State != auth.SignInStateRejected {
		t.Fatal("public request reset retained old-password signin", e)
	}
	if login, e := resetTestSignin(t, ctx, service.pool, signin, signinConfig, canonical, []byte("synthetic-full-public-reset")); e != nil || login.State != auth.SignInStateAuthenticated {
		t.Fatal("public request reset cannot authenticate replacement password", e)
	}
	for _, mode := range []string{"missing", "enrolled", "unknown-factor"} {
		t.Run(mode, func(t *testing.T) {
			suppressed := r
			suppressed.CommandID, _ = identity.NewCommandID()
			suppressed.Caller = r.Caller.Clone()
			suppressed.Caller.CorrelationID = string(suppressed.CommandID)
			suppressed.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("synthetic-public-reset-" + mode))
			if mode == "missing" {
				suppressed.Identifier = "missing-reset@example.test"
			} else if mode == "enrolled" {
				if _, e := service.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND canonical_value=$2)`, signinTestTenant, canonical); e != nil {
					t.Fatal(e)
				}
				defer service.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0 WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND canonical_value=$2)`, signinTestTenant, canonical)
			} else {
				// This existing verified/password-backed fixture remains selected,
				// but its independent MFA owner state is genuinely absent.
				var user, version, purpose string
				var initialization []byte
				var active int32
				if e := service.pool.Raw().QueryRow(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=(SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND canonical_value=$2) RETURNING user_id,version::text,active_factors,initialized_command_id,initialized_purpose`, signinTestTenant, canonical).Scan(&user, &version, &active, &initialization, &purpose); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := service.pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$2,$3::numeric,$4,$5,$6)`, signinTestTenant, user, version, active, initialization, purpose); e != nil {
						t.Fatal(e)
					}
				}()
			}
			result, e := public.ResetRequest(ctx, suppressed)
			if e != nil || !result.Accepted || result.Outcome != accepted.Outcome {
				t.Fatal("suppressed reset enumerated", e)
			}
			command, _ := base64.RawURLEncoding.DecodeString(string(result.CommandID))
			var messages, grants int
			if e := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, command, string(result.CommandID)).Scan(&messages, &grants); e != nil || messages != 0 || grants != 0 {
				t.Fatal("suppressed request issued or delivered", e)
			}
		})
	}
	t.Run("audit rollback", func(t *testing.T) {
		failed := r
		failed.CommandID, _ = identity.NewCommandID()
		failed.Caller = r.Caller.Clone()
		failed.Caller.CorrelationID = string(failed.CommandID)
		failed.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("synthetic-public-request-audit-rollback"))
		if _, e := service.pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT reset_request_failure CHECK(false) NOT VALID`); e != nil {
			t.Fatal(e)
		}
		defer service.pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT IF EXISTS reset_request_failure`)
		result, e := public.ResetRequest(ctx, failed)
		if e == nil || result.Accepted || result.Outcome == identity.CommitOutcomeCommitted || result.CommandID == "" {
			t.Fatal("request audit failure acknowledged issuance", e)
		}
		command, _ := base64.RawURLEncoding.DecodeString(string(result.CommandID))
		var messages, grants int
		if e := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, command, string(result.CommandID)).Scan(&messages, &grants); e != nil || messages != 0 || grants != 0 {
			t.Fatal("request rollback retained issuance/delivery", e)
		}
		if _, e := service.pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT reset_request_failure`); e != nil {
			t.Fatal(e)
		}
		if _, e := service.pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, command); e != nil {
			t.Fatal(e)
		}
		q := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: result.CommandID, AnonymousFlowID: string(failed.CommandID), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: resetRequestOperation().OperationID}
		// A nonmatching retained grant for this origin is conflicting evidence,
		// not absence. Never terminalize a rollback by checking only the exact
		// proposed grant/replay identities. This row is synthetic corruption in
		// the disposable fixture, not a production issuance operation.
		const conflicting = "synthetic-conflicting-reset-issuance"
		insert, e := service.pool.Raw().Exec(ctx, `INSERT INTO capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) SELECT tenant_id,purpose,replay_key_version,$4,$3,proof_fingerprint,expires_at,max_uses,$1,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at FROM capability_identity_one_use WHERE origin_command_id=$2`, string(result.CommandID), string(accepted.CommandID), conflicting, bytes.Repeat([]byte{109}, 32))
		if e != nil || insert.RowsAffected() != 1 {
			t.Fatal("conflicting original-issuer fixture", e)
		}
		if observed, e := public.RecoverResetRequest(ctx, q, failed.Caller); e == nil || observed.Outcome == identity.CommitOutcomeNotCommitted || observed.Accepted {
			t.Fatal("conflicting issuance evidence was treated as rollback", e)
		}
		if deleted, e := service.pool.Raw().Exec(ctx, `DELETE FROM capability_identity_one_use WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3`, signinTestTenant, resetOperation().OperationID, conflicting); e != nil || deleted.RowsAffected() != 1 {
			t.Fatal("conflicting original-issuer fixture cleanup", e)
		}
		recovered, e := public.RecoverResetRequest(ctx, q, failed.Caller)
		var dependency identity.UnavailableError
		if !errors.As(e, &dependency) || recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Accepted {
			t.Fatal("request rollback cannot reconcile original absent effects", e)
		}
	})
	t.Run("completion disconnect recovery", func(t *testing.T) {
		testResetCompletionDisconnect(t, ctx, service, keys, mail, mailCrypto, r, signin, signinConfig)
	})
	for _, before := range []bool{true, false} {
		name := "disconnect-after-commit"
		if before {
			name = "disconnect-before-commit"
		}
		t.Run(name, func(t *testing.T) {
			fault := &signinCommitFault{before: before, marker: "INSERT INTO identity.delivery_intents"}
			pool, e := database.Connect(ctx, database.Config{DSN: service.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
			if e != nil {
				t.Fatal("request fault pool unavailable")
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if pool.Close(cleanup) != nil {
					t.Error("request fault pool cleanup")
				}
			}()
			config := c
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			interrupted, e := NewResetService(pool, config, keys)
			if e != nil {
				t.Fatal("interrupted request composition", e)
			}
			restarted, e := NewResetService(service.pool, config, keys)
			if e != nil {
				t.Fatal("restarted request composition", e)
			}
			request := r
			request.CommandID, _ = identity.NewCommandID()
			request.Caller = r.Caller.Clone()
			request.Caller.CorrelationID = string(request.CommandID)
			request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("synthetic-reset-request-" + name))
			original, e := interrupted.ResetRequest(ctx, request)
			if e == nil || !fault.hit.Load() || original.Accepted || original.Outcome != identity.CommitOutcomeUnknown || original.CommandID == "" {
				t.Fatal("request disconnect fabricated acceptance or outcome", e)
			}
			command, e := base64.RawURLEncoding.DecodeString(string(original.CommandID))
			if e != nil || len(command) != 16 {
				t.Fatal("request disconnect lost original command")
			}
			want, outcome := 1, identity.CommitOutcomeCommitted
			if before {
				want, outcome = 0, identity.CommitOutcomeNotCommitted
			}
			assertEffects := func(wantAudit, wantAuditOutcome int) {
				t.Helper()
				var messages, grants, audits, events, auditOutcome int
				if e := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT COALESCE(max(r.outcome),0) FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1)`, command, string(original.CommandID)).Scan(&messages, &grants, &audits, &events, &auditOutcome); e != nil || messages != want || grants != want || audits != wantAudit || events != want || auditOutcome != wantAuditOutcome {
					t.Fatal("request disconnect split issuance and required effects", e)
				}
			}
			assertEffects(want, want)
			query := identity.RecoveryQuery{TenantID: request.TenantID, CommandID: original.CommandID, AnonymousFlowID: string(request.CommandID), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: resetRequestOperation().OperationID}
			bounded, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				recovered, err := restarted.RecoverResetRequest(bounded, query, request.Caller)
				if recovered.Outcome == outcome {
					var unavailable identity.UnavailableError
					if recovered.CommandID != original.CommandID || recovered.Accepted != !before || (!before && err != nil) || (before && !errors.As(err, &unavailable)) {
						t.Fatal("request recovery changed original result", err)
					}
					break
				}
				select {
				case <-bounded.Done():
					t.Fatal("request disconnect outcome unresolved", err)
				case <-ticker.C:
				}
			}
			for i := 0; i < 2; i++ {
				recovered, err := restarted.RecoverResetRequest(ctx, query, request.Caller)
				if recovered.CommandID != original.CommandID || recovered.Outcome != outcome || recovered.Accepted != !before || (!before && err != nil) {
					t.Fatal("repeated request recovery changed original outcome", err)
				}
				// Proved noncommit terminalizes with one failure audit, not a
				// success/lifecycle effect; later recovery must not duplicate it.
				auditOutcome := 1
				if before {
					auditOutcome = 2
				}
				assertEffects(1, auditOutcome)
			}
		})
	}
}
