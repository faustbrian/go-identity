//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func testOwnedProviderPreAuthIssue(t *testing.T, ctx context.Context, pool *database.Pool, base IssueExecutorConfig) {
	t.Helper()
	base.Coordinator.FinalAuthentication = nil
	config := PreAuthIssueExecutorConfig{Repository: base.Repository, Coordinator: base.Coordinator, Authorization: base.Authorization, Clock: base.Clock, ActorID: "provider-preauth-service", Action: "identity.oauth.onetap-start", Origin: "https://identity.test", PolicyID: "login", PolicyVersion: 1, AuditRetentionVersion: 1}
	selected := session.PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "synthetic-onetap-client", Mode: session.PreAuthProviderCallback}
	key, err := session.NewDigestKey(19, bytes.Repeat([]byte{19}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuerConfig := session.PreAuthIssuerConfig{ActorID: config.ActorID, Action: config.Action, Origin: config.Origin, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion, Clock: config.Clock, MaximumDuration: 2 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Cookie: cookie}
	newIssuer := func(t *testing.T, c PreAuthIssueExecutorConfig, provider session.PreAuthProviderBinding) (*PreAuthIssueExecutor, *session.PreAuthIssuer) {
		t.Helper()
		executor, err := NewProviderPreAuthIssueExecutor(pool, c, provider)
		if err != nil {
			t.Fatal("construct native callback executor", err)
		}
		issuer, err := session.NewProviderPreAuthIssuer(executor, issuerConfig, provider)
		if err != nil {
			t.Fatal("compose callback issuer", err)
		}
		return executor, issuer
	}
	prepare := func(t *testing.T, issuer *session.PreAuthIssuer, choice session.RememberChoice) session.PreparedPreAuthIssuance {
		t.Helper()
		remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: "issue", CorrelationID: "native-onetap-callback", Remember: remember})
		if err != nil {
			t.Fatal("prepare original callback", err)
		}
		return prepared
	}
	noDelivery := func(t *testing.T, out session.PreAuthIssueResult) {
		t.Helper()
		if !reflect.DeepEqual(out.Cookie, http.Cookie{}) {
			t.Fatal("historical or uncommitted command returned a cookie")
		}
		if _, err := out.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) {
			t.Fatal("historical or uncommitted command returned a credential")
		}
	}
	row := func(t *testing.T, tenant identity.TenantID, id identity.PreAuthTransactionID) string {
		t.Helper()
		var snapshot string
		if err := pool.Raw().QueryRow(ctx, `SELECT to_jsonb(p)::text FROM session_store.preauth_transactions p WHERE tenant_id=$1 AND flow_id=$2`, string(tenant), string(id)).Scan(&snapshot); err != nil {
			t.Fatal("read exact persisted flow snapshot", err)
		}
		return snapshot
	}
	counts := func(t *testing.T, command PreAuthIssueCommand, want int) {
		t.Helper()
		original, err := command.Record.ProviderBindings()
		if err != nil {
			t.Fatal(err)
		}
		var flows, evidence, audits, events, commands int
		err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2),(SELECT count(*) FROM session_store.preauth_issuances WHERE command_id=$3),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$3),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3),(SELECT count(*) FROM identity.commands WHERE command_id=$3)`, string(original.Transaction.Binding.Intent.TenantID), string(original.Transaction.Binding.ID), mustCommandBytes(t, command.CommandID)).Scan(&flows, &evidence, &audits, &events, &commands)
		if err != nil || flows != want || evidence != want || audits != want || events != want || commands != want {
			t.Fatal("native flow/evidence/audit/lifecycle/command conservation", flows, evidence, audits, events, commands, err)
		}
	}

	legacyConfig := config
	legacyConfig.Action, legacyConfig.CallbackURL = "identity.otp.signin", "https://app.test/return"
	legacyExecutor, err := NewPreAuthIssueExecutor(pool, legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	legacyIssuerConfig := issuerConfig
	legacyIssuerConfig.Action, legacyIssuerConfig.CallbackURL = legacyConfig.Action, legacyConfig.CallbackURL
	legacyIssuer, err := session.NewPreAuthIssuer(legacyExecutor, legacyIssuerConfig)
	if err != nil {
		t.Fatal(err)
	}
	legacyPrepared := prepare(t, legacyIssuer, session.BrowserSession)
	legacyCommand, _ := legacyPrepared.Command()
	legacy, err := legacyIssuer.Issue(ctx, legacyPrepared)
	if err != nil || legacy.CommitOutcome != identity.CommitOutcomeCommitted || legacy.Replayed {
		t.Fatal("seed independent legacy flow", err)
	}
	legacySpec, err := legacyCommand.Record.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore := row(t, legacySpec.Binding.Intent.TenantID, legacySpec.Binding.ID)
	legacyPayload, err := encodePreAuth(legacyCommand.Record)
	if err != nil {
		t.Fatal(err)
	}
	var sessionsBefore, familiesBefore int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM session_store.families)`).Scan(&sessionsBefore, &familiesBefore); err != nil {
		t.Fatal(err)
	}

	for _, profile := range []struct {
		name   string
		choice session.RememberChoice
	}{{"browser session", session.BrowserSession}, {"persistent session", session.PersistentSession}} {
		t.Run(profile.name, func(t *testing.T) {
			var expectedFlow identity.PreAuthTransactionID
			observedCalls := 0
			authorized := config
			authorized.Authorization = issueDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				observedCalls++
				if dc.Request.Tenant != "issue" || dc.Request.Subject.Kind != authorization.SubjectServiceAccount || dc.Request.Subject.ID != authorization.SubjectID(config.ActorID) || dc.Request.Action != authorization.Action(session.PreAuthIssueOperation().OperationID) || dc.Request.Resource.Type != "identity.anonymous-flow" || dc.Request.Resource.ID != authorization.ResourceID(expectedFlow) {
					t.Fatal("callback initiation confused anonymous flow, service actor or tenant")
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
			executor, issuer := newIssuer(t, authorized, selected)
			prepared := prepare(t, issuer, profile.choice)
			command, _ := prepared.Command()
			original, err := command.Record.ProviderBindings()
			if err != nil {
				t.Fatal(err)
			}
			spec := original.Transaction
			expectedFlow = spec.Binding.ID
			remember, err := spec.Binding.Intent.Remember.Bindings()
			if err != nil || remember.Choice != profile.choice || original.Provider != selected || spec.Binding.Intent.Action != config.Action || spec.Binding.Intent.Origin != config.Origin || spec.Binding.Intent.CallbackURL != "" || spec.Binding.Intent.Nonce == ([32]byte{}) || spec.Binding.ExpiresAt.Sub(spec.Binding.IssuedAt) != 5*time.Minute || spec.Version != 1 {
				t.Fatal("prepared callback changed original provider, nonce, timeline or remember policy", err)
			}
			out, err := issuer.Issue(ctx, prepared)
			if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed || out.Flow != command.Record || observedCalls == 0 {
				t.Fatal("fresh native commitment did not release the original callback", err)
			}
			if out.Cookie.Name != "__Host-identity_flow" || out.Cookie.Path != "/" || out.Cookie.Domain != "" || out.Cookie.Value != "" || !out.Cookie.Secure || !out.Cookie.HttpOnly || out.Cookie.SameSite != http.SameSiteLaxMode || out.Cookie.MaxAge < 1 || out.Cookie.MaxAge > 300 || out.Cookie.Expires.After(spec.Binding.ExpiresAt) {
				t.Fatal("fresh callback cookie weakened host scope or original expiry")
			}
			wire, err := out.Token.Reveal()
			if err != nil {
				t.Fatal("new native commit withheld callback credential", err)
			}
			token, err := session.ParseToken(wire)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := token.ProviderPreAuthDigest(key, spec.Binding, selected)
			if err != nil || digest != spec.Cookie || command.Record.CheckProvider(config.Clock.Now(), spec.Binding, selected, digest) != nil {
				t.Fatal("released credential does not authenticate original provider commitment", err)
			}
			counts(t, command, 1)
			before := row(t, "issue", expectedFlow)
			if legacyRead, err := ReadPreAuth(ctx, pool.Raw(), config.Repository, "issue", expectedFlow); err == nil || legacyRead != (session.PreAuthTransaction{}) {
				t.Fatal("legacy reader accepted provider-bound bytes")
			}
			restarted, restartedIssuer := newIssuer(t, authorized, selected)
			loaded, err := ReadProviderPreAuth(ctx, pool.Raw(), config.Repository, "issue", expectedFlow, selected)
			if err != nil {
				t.Fatal("restart read lost provider-bound original", err)
			}
			loadedSpec, err := loaded.ProviderBindings()
			if err != nil || !reflect.DeepEqual(loadedSpec, original) || loaded.CheckProvider(config.Clock.Now(), spec.Binding, selected, digest) != nil {
				t.Fatal("restart changed exact original persisted payload or cookie digest", err)
			}
			recovered, err := restartedIssuer.Recover(ctx, command)
			if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Flow != (session.PreAuthTransaction{}) {
				t.Fatal("restart returned more than the original historical outcome", err)
			}
			noDelivery(t, recovered)
			replay, err := restarted.ExecutePreAuthIssuance(ctx, command)
			if err != nil || !replay.Replayed || replay.Receipt.Outcome != identity.CommitOutcomeCommitted || replay.Receipt.Validate() != nil {
				t.Fatal("equal retained command reexecuted instead of observing history", err)
			}
			binding := replay.Receipt.Binding
			if binding.CommandID != command.CommandID || binding.TenantID != "issue" || binding.UserID != "" || binding.AnonymousFlowID != string(expectedFlow) || binding.RecordID != string(expectedFlow) || binding.ActorID != config.ActorID || binding.ActorKind != authorization.SubjectServiceAccount || binding.LinkMode != 0 {
				t.Fatal("native historical receipt changed anonymous actor/target matching")
			}
			if repeated, err := issuer.Issue(ctx, prepared); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
				t.Fatal("same preparation acquired another delivery", err)
			} else {
				noDelivery(t, repeated)
			}
			for _, variation := range []struct {
				name   string
				change func(*session.PreAuthProviderBinding)
			}{{"provider version", func(p *session.PreAuthProviderBinding) { p.ProviderVersion++ }}, {"client", func(p *session.PreAuthProviderBinding) { p.ClientID = "another-synthetic-client" }}} {
				t.Run(variation.name, func(t *testing.T) {
					other := selected
					variation.change(&other)
					if got, err := ReadProviderPreAuth(ctx, pool.Raw(), config.Repository, "issue", expectedFlow, other); err == nil || got != (session.PreAuthTransaction{}) {
						t.Fatal("another startup provider read the original flow")
					}
					rotated, rotatedIssuer := newIssuer(t, authorized, other)
					if got, err := rotated.ExecutePreAuthIssuance(ctx, command); err == nil || !got.Replayed || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("another startup provider borrowed original execution", err)
					}
					if got, err := rotatedIssuer.Recover(ctx, command); err == nil {
						t.Fatal("another startup provider recovered original authority")
					} else {
						noDelivery(t, got)
					}
					substitution := original
					substitution.Provider = other
					changed := command
					changed.Record, err = session.NewProviderPreAuthTransaction(substitution)
					if err != nil {
						t.Fatal(err)
					}
					if got, err := rotated.ExecutePreAuthIssuance(ctx, changed); err == nil || !got.Replayed || got.Receipt.Outcome != identity.CommitOutcomeConflict {
						t.Fatal("same-command provider substitution did not conflict", err)
					}
				})
			}
			changedSpec := original
			changedSpec.Transaction.Binding.Intent.Nonce[0] ^= 1
			changed := command
			changed.Record, err = session.NewProviderPreAuthTransaction(changedSpec)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := executor.ExecutePreAuthIssuance(ctx, changed); err == nil || !got.Replayed || got.Receipt.Outcome != identity.CommitOutcomeConflict {
				t.Fatal("same-command nonce substitution did not conflict", err)
			}
			if after := row(t, "issue", expectedFlow); after != before {
				t.Fatal("restart, replay or denied substitution changed original durable flow")
			}
			counts(t, command, 1)
			t.Run("callback uses the original flow once", func(t *testing.T) {
				testIssuedProviderPreAuthConsumption(t, ctx, pool, config.Repository, loaded, selected, config.ActorID)
			})
		})
	}

	t.Run("current denial withholds cookie and all native effects", func(t *testing.T) {
		denied := config
		denied.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		})
		_, issuer := newIssuer(t, denied, selected)
		prepared := prepare(t, issuer, session.PersistentSession)
		command, _ := prepared.Command()
		out, err := issuer.Issue(ctx, prepared)
		if err == nil || out.CommitOutcome == identity.CommitOutcomeCommitted {
			t.Fatal("denied provider callback committed")
		}
		noDelivery(t, out)
		counts(t, command, 0)
	})
	legacyLoaded, err := ReadPreAuth(ctx, pool.Raw(), config.Repository, legacySpec.Binding.Intent.TenantID, legacySpec.Binding.ID)
	if err != nil {
		t.Fatal("provider initiation broke unrelated legacy read", err)
	}
	legacyAfter, err := encodePreAuth(legacyLoaded)
	if err != nil || !bytes.Equal(legacyAfter, legacyPayload) || row(t, legacySpec.Binding.Intent.TenantID, legacySpec.Binding.ID) != legacyBefore {
		t.Fatal("provider initiation changed unrelated exact legacy state", err)
	}
	var sessionsAfter, familiesAfter int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM session_store.families)`).Scan(&sessionsAfter, &familiesAfter); err != nil || sessionsAfter != sessionsBefore || familiesAfter != familiesBefore {
		t.Fatal("callback initiation created authenticated session or family state", err)
	}
}

func testIssuedProviderPreAuthConsumption(t *testing.T, ctx context.Context, pool *database.Pool, config Config, record session.PreAuthTransaction, selected session.PreAuthProviderBinding, actor identity.ActorID) {
	t.Helper()
	original, err := record.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	binding := original.Transaction.Binding
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	use := PreAuthUse{Command: identity.CommandBinding{
		CommandID: id, TenantID: binding.Intent.TenantID, AnonymousFlowID: string(binding.ID), ActorID: actor,
		ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.oauth.onetap-callback", RecordID: string(binding.ID),
		PolicyID: binding.Intent.PolicyID, PolicyVersion: binding.Intent.PolicyVersion, SchemaID: "oauth-onetap-callback-v1",
		SchemaVersion: 1, CorrelationID: "native-onetap-completion",
	}, Fingerprint: [32]byte{23}, Generation: 1}
	begin := func() preAuthTestTx {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		})
		return preAuthTestTx{tx}
	}
	reserveAndFinalize := func(q preAuthTestTx) {
		t.Helper()
		if err := RequireProviderPreAuth(ctx, q, config, record, selected); err != nil {
			t.Fatal("exact issued flow was not admitted", err)
		}
		if err := ReserveProviderPreAuth(ctx, q, config, record, selected, use); err != nil {
			t.Fatal("callback could not reserve the exact original", err)
		}
		wrongOwner := use
		wrongOwner.Generation++
		if err := FinalizeProviderPreAuth(ctx, q, config, record, selected, wrongOwner); err == nil {
			t.Fatal("another command generation consumed the original")
		}
		if err := FinalizeProviderPreAuth(ctx, q, config, record, selected, use); err != nil {
			t.Fatal("exact callback owner could not consume the reserved flow", err)
		}
	}

	q := begin()
	wrongProvider := selected
	wrongProvider.ClientID = "another-synthetic-client"
	if err := RequireProviderPreAuth(ctx, q, config, record, wrongProvider); err == nil {
		t.Fatal("another configured client admitted the original")
	}
	wrongAction := use
	wrongAction.Command.OperationID = "identity.oauth.callback"
	if err := ReserveProviderPreAuth(ctx, q, config, record, selected, wrongAction); err == nil {
		t.Fatal("ordinary OAuth callback borrowed the One Tap flow")
	}
	otherFlow := use
	otherFlow.Command.AnonymousFlowID = "another-flow"
	if err := ReserveProviderPreAuth(ctx, q, config, record, selected, otherFlow); err == nil {
		t.Fatal("another anonymous flow borrowed the original")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := ReserveProviderPreAuth(canceled, q, config, record, selected, use); err == nil {
		t.Fatal("canceled callback reserved the original")
	}
	if err := ReservePreAuth(ctx, q, config, record, use); err == nil {
		t.Fatal("legacy reservation accepted a provider-bound record")
	}
	reserveAndFinalize(q)
	if err := q.Rollback(ctx); err != nil {
		t.Fatal("roll back the protected invocation", err)
	}

	q = begin()
	reserveAndFinalize(q)
	if err := q.Commit(ctx); err != nil {
		t.Fatal("commit the protected invocation", err)
	}

	q = begin()
	if err := RequireProviderPreAuth(ctx, q, config, record, selected); err == nil {
		t.Fatal("consumed flow was admitted again")
	}
	if err := ReserveProviderPreAuth(ctx, q, config, record, selected, use); err == nil {
		t.Fatal("terminal consumption reopened for the same command")
	}
	var state, version string
	if err := q.QueryRow(ctx, `SELECT state,version::text FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(binding.Intent.TenantID), string(binding.ID)).Scan(&state, &version); err != nil || state != "consumed" || version != "3" {
		t.Fatal("callback did not preserve the terminal original", state, version, err)
	}
	if err := q.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}
