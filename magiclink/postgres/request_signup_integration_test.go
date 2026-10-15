//go:build integration

package magiclinkpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Intermediate native journal integration, not public signup delivery. The
// public operation stays disabled until the actual consuming path is complete.
func exerciseProspectiveRequestGeneration(t *testing.T, ctx context.Context, pool *database.Pool, config RequestConfig, keys *keyring.Provider, flowKey session.DigestKey, normalization identifier.NormalizationProfile) {
	identifierHistory := kernel.IdentifierMutationMigrationSource{Base: kernel.MigrationSource{}, Version: 17}
	registrationHistory := kernel.PasswordRegistrationMigrationSource{Base: identifierHistory, Version: 18}
	acceptanceHistory := kernel.PasswordSignupAcceptanceMigrationSource{Base: registrationHistory, Version: 19}
	history, err := (kernel.MagicLinkRegistrationMigrationSource{Base: acceptanceHistory, Version: 21}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() >= 17 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("identifier retirement history", err)
			}
		}
	}
	factorHistory, err := (mfapg.MagicLinkSignupMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range factorHistory {
		if m.Version() == 2 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("factor signup history", err)
			}
		}
	}
	config.Signup = &SignupConfig{SchemaID: "signup-fields", SchemaVersion: 1, Domain: kernel.MagicLinkRegistrationDomainConfig{ComparisonProfile: "magic-email", EmailPossessionPolicyVersion: 9, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {104}}}}
	config.Possession, err = email.NewMagicLinkPossessionPolicy(email.MagicLinkPossessionConfig{Address: email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization}, Issuer: config.IssuerURL, Audience: config.Issuer.Audience, MaximumLifetime: config.Lifetime, Callbacks: config.Callbacks, Version: 9})
	if err != nil {
		t.Fatal(err)
	}
	config.Issuer.Crypto.Limits.MaxCaveats = 18
	s, err := NewRequestService(pool, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unused", "collision", "rollback", "unverified", "banned"} {
		t.Run(mode, func(t *testing.T) {
			canonical := "prospective-" + mode + "@example.test"
			available := mode == "unused" || mode == "collision" || mode == "rollback"
			if !available {
				status := "active"
				if mode == "banned" {
					status = "banned"
				}
				_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,$3,1)`, requestTestTenant, "occupant-"+mode, status)
				if err != nil {
					t.Fatal(err)
				}
				_, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES($1,$2,$3,'email',$4,1,1,1)`, requestTestTenant, "occupant-"+mode, "mailbox-"+mode, canonical)
				if err != nil {
					t.Fatal(err)
				}
			}
			id, _ := identity.NewCommandID()
			flowID, _ := identity.NewPreAuthTransactionID()
			raw := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{105}, 32))
			token, _ := session.ParseToken(raw)
			remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
			now := time.Now().UTC().Truncate(time.Microsecond)
			binding := session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: requestTestTenant, Action: "identity.magic-link.consume", Origin: "https://app.test", CallbackURL: "https://app.test/login", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login", PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			digest, _ := token.PreAuthDigest(flowKey, binding)
			flow, _ := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
			if err := sessionpg.InsertPreAuth(ctx, requestTestTx{pool}, config.Session, flow); err != nil {
				t.Fatal(err)
			}
			key, _ := identity.NewIdempotencyKey([]byte("prospective-" + mode))
			r := magiclink.RequestRequest{TenantID: requestTestTenant, CommandID: id, Email: email.AddressInput(canonical), Intent: magiclink.SignupIfAllowed, Callback: "https://app.test/login", IdempotencyKey: key, PreAuthID: flowID, Cookie: auth.NewBearerCredential(raw), Origin: "https://app.test", Network: "192.0.2.1", Device: "fixture", Caller: authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: requestTestTenant, Action: "identity.magic-link.request", Subject: authorization.Subject{ID: "ingress", Kind: authorization.SubjectServiceAccount}}}}
			b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, AnonymousFlowID: string(flowID), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: requestOperation().OperationID, SchemaID: requestOperation().SchemaID, SchemaVersion: 1, PolicyID: "login", PolicyVersion: 3, CorrelationID: string(id)}
			original, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: requestOperation(), Fields: []identity.FeatureField{{Name: "request.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "native-prospective-test"}}}})
			if err != nil {
				t.Fatal(err)
			}
			selected, err := s.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
			if err != nil || !selected.Suppressed {
				t.Fatal("fixture is not a suppressed directory selection", err)
			}
			p := &requestPhase{service: s, request: r, original: original, canonical: canonical, flow: flow, selected: requestSelection{recipient: selected}, subject: risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
			coordinator, _, err := s.coordinator(p)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := p.plan(now, false)
			if err != nil {
				t.Fatal(err)
			}
			if p.selected.prospective != nil {
				t.Fatal("identity allocated before generation admission")
			}
			result, err := coordinator.ExecutePreparedFeature(ctx, original, plan)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("native prospective request", err)
			}
			replayed, err := coordinator.ExecutePreparedFeature(ctx, original, plan)
			if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("native prospective request replay regenerated or changed outcome", err)
			}
			var messages, grants int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, mustCommandBytes(t, id), string(id)).Scan(&messages, &grants); err != nil {
				t.Fatal(err)
			}
			want := 0
			if available {
				want = 1
			}
			if messages != want || grants != want {
				t.Fatal("native request lost prospective issuance or generated for occupied mailbox")
			}
			if available {
				if p.execution == nil || p.execution.selected.prospective == nil || !p.execution.selected.recipient.Suppressed || p.execution.selected.factor != 0 {
					t.Fatal("retained output fabricated current identity/factor")
				}
				var exists bool
				if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2)`, requestTestTenant, string(p.execution.selected.prospective.Creation.Binding.UserID)).Scan(&exists); err != nil || exists {
					t.Fatal("request created account before link consumption", err)
				}
				proof := captureMagicLinkDeliveryFor(t, ctx, pool, config, s.crypto, canonical, true)
				grant, origin, _, _, err := s.issuer.ReadMagicLinkOrigin(ctx, pool, proof)
				if err != nil || origin != id {
					t.Fatal("actual signup delivery has no durable issuance origin", err)
				}
				consumeID, _ := identity.NewCommandID()
				input := magiclink.ConsumeRequest{TenantID: r.TenantID, CommandID: consumeID, PreAuthID: flowID, Cookie: r.Cookie, Callback: r.Callback, Origin: r.Origin, Token: proof, Caller: r.Caller, Network: r.Network, Device: r.Device}
				input.Caller.Request.Action = "identity.magic-link.consume"
				input.Caller.CorrelationID = string(consumeID)
				retained, err := s.readProspectiveOrigin(ctx, input, flow, grant, origin)
				if err != nil || retained.prospective == nil {
					t.Fatal("original encrypted signup intent unavailable to consume", err)
				}
				before, _ := kernel.MagicLinkRegistrationDigest(*p.execution.selected.prospective)
				after, _ := kernel.MagicLinkRegistrationDigest(*retained.prospective)
				if before != after || retained.factor != 0 || !retained.recipient.Suppressed {
					t.Fatal("consuming read reconstructed or fabricated original intent")
				}
				foreign := input
				foreign.Caller = input.Caller.Clone()
				foreign.Caller.Request.Subject.ID = "foreign-ingress"
				if _, err := s.readProspectiveOrigin(ctx, foreign, flow, grant, origin); err == nil {
					t.Fatal("foreign original actor read signup custody")
				}
				foreign = input
				foreign.Callback = "https://app.test/login?other=1"
				if _, err := s.readProspectiveOrigin(ctx, foreign, flow, grant, origin); err == nil {
					t.Fatal("changed callback read signup custody")
				}
				lookup, _ := session.NewDigestKey(1, bytes.Repeat([]byte{106}, 32))
				csrf, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{107}, 32))
				cookiePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-signup", SameSite: http.SameSiteLaxMode})
				consumer, err := NewConsumeService(s, ConsumeConfig{ConfigurationID: "signup-consume-v1", PolicyNamespace: "users", Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookiePolicy}, CSRF: csrf})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "collision" {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'late-occupant','active',1);`, requestTestTenant); err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES($1,'late-occupant','late-mailbox','email',$2,1,1,1)`, requestTestTenant, canonical); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "rollback" {
					if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION identity_mfa.deny_magic_signup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test injected factor persistence failure'; END $$; CREATE TRIGGER deny_magic_signup BEFORE INSERT ON identity_mfa.factor_authorities FOR EACH ROW EXECUTE FUNCTION identity_mfa.deny_magic_signup()`); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER deny_magic_signup ON identity_mfa.factor_authorities; DROP FUNCTION identity_mfa.deny_magic_signup()`); err != nil {
							t.Error(err)
						}
					}()
				}
				consumed, err := consumer.Consume(ctx, input)
				if mode != "unused" {
					if err == nil || consumed.Session.Token != (session.Token{}) || consumed.CSRFToken != (session.CSRFToken{}) {
						t.Fatal("failed signup delivered credentials")
					}
					var accounts, factors, uses int
					if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2),(SELECT uses FROM capability_identity_one_use WHERE origin_command_id=$3)`, requestTestTenant, string(retained.prospective.Creation.Binding.UserID), string(origin)).Scan(&accounts, &factors, &uses); err != nil || accounts != 0 || factors != 0 || uses != 0 {
						t.Fatal("failed signup retained partial account/factor/use effects", err)
					}
					var events int
					if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2`, requestTestTenant, mustCommandBytes(t, input.CommandID)).Scan(&events); err != nil || events != 0 {
						t.Fatal("failed signup retained lifecycle effects", err)
					}
					return
				}
				if err != nil || consumed.Outcome != identity.CommitOutcomeCommitted || consumed.State != auth.SignInStateAuthenticated {
					t.Fatal("real original signup link did not create and authenticate", err)
				}
				if consumed.Session.Token == (session.Token{}) || consumed.CSRFToken == (session.CSRFToken{}) || consumed.Session.Cookie.Name != "__Host-signup" || consumed.Session.Cookie.Value != "" {
					t.Fatal("signup committed without original transport custody")
				}
				var accounts, factors, uses int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 AND version=1 AND active_factors=0),(SELECT uses FROM capability_identity_one_use WHERE origin_command_id=$3)`, requestTestTenant, string(retained.prospective.Creation.Binding.UserID), string(origin)).Scan(&accounts, &factors, &uses); err != nil || accounts != 1 || factors != 1 || uses != 1 {
					t.Fatal("signup effects are not atomic real authority", err)
				}
				var events int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2 AND event_index IN (0,1)`, requestTestTenant, mustCommandBytes(t, input.CommandID)).Scan(&events); err != nil || events != 2 {
					t.Fatal("signup did not persist both account and session lifecycle", err)
				}
				bearer, err := consumed.Session.Token.Reveal()
				if err != nil {
					t.Fatal("signup bearer custody", err)
				}
				parsed, err := session.ParseToken(bearer)
				if err != nil {
					t.Fatal(err)
				}
				credential, err := session.NewCredential(session.CredentialCookie, parsed)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := sessionpg.NewMagicLinkSessionService(pool, sessionpg.MagicLinkSessionServiceConfig{Repository: config.Session, Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: config.GlobalAuthorityID, PolicyNamespace: "users", Audience: config.Issuer.Audience}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Issuer.Audience, Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
				if err != nil {
					t.Fatal(err)
				}
				if live, err := reader.Get(ctx, session.GetRequest{TenantID: input.TenantID, Credential: credential}); err != nil || !live.Authenticated {
					t.Fatal("new signup session lacks live authority", err)
				}
				replayed, err := consumer.Consume(ctx, input)
				if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Session.Replayed || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("signup retry regenerated session custody", err)
				}
				q := identity.RecoveryQuery{TenantID: input.TenantID, CommandID: input.CommandID, AnonymousFlowID: string(input.PreAuthID), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.magic-link.consume"}
				if recovered, err := consumer.RecoverConsume(ctx, q, input.Caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("signup recovery fabricated custody", err)
				}
				competing := input
				competing.CommandID, _ = identity.NewCommandID()
				if result, err := consumer.Consume(ctx, competing); err == nil || result.Session.Token != (session.Token{}) {
					t.Fatal("second command reused consumed signup link")
				}
			}
		})
	}
}
