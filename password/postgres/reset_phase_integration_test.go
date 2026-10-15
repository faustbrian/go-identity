//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type resetFailingAudit struct{ *auditpg.IdentityContributor }

type resetPreparationReader interface {
	QueryFeaturePreparation(context.Context, identity.RecoveryQuery, authorization.DecisionContext, kernel.FeatureRegistration, kernel.FeaturePreparationContributor) ([]byte, uint64, error)
}

func (p *resetFailingAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	if err := p.IdentityContributor.PersistAudits(ctx, w); err != nil {
		return err
	}
	return identity.UnavailableError{}
}

// Real preparation, MFA, password material, kernel, sessions, one-use, audit
// and outbox SQL. Issued metadata and verified email are explicit fixtures;
// risk/provider IO use the existing deliberate boundaries. This does not claim
// a public request/delivery/HTTP journey or production issuance provenance.
func testNativeResetCompletion(t *testing.T, ctx context.Context, pool *database.Pool, directory *kernel.Repository, policy primitive.Policy, crypto *primitive.Service, base kernel.DirectoryAuthorityMigrationSource) {
	t.Helper()
	registration := kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.PasswordRegistrationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: base, Version: 14}, Version: 15}, Version: 16}
	history, err := (kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.CredentialResetMigrationSource{Base: registration, Version: 17}, Version: 18}, Version: 19}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() >= 17 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	history, err = (sessionpg.PasswordResetMigrationSource{Schema: "signin_sessions", Version: 9}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	wire, err := fs.ReadFile(capabilitypg.Migrations(), "001_identity_one_use.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
		t.Fatal(err)
	}
	var user, canonical string
	if err := pool.Raw().QueryRow(ctx, `SELECT f.user_id,i.canonical_value FROM identity_mfa.factor_authorities f JOIN identity.identifiers i USING(tenant_id,user_id) WHERE f.tenant_id=$1 ORDER BY f.user_id LIMIT 1`, signinTestTenant).Scan(&user, &canonical); err != nil {
		t.Fatal(err)
	}
	// Only setup mutates verification. The tested completion must fence the
	// selected verified row and may neither verify an address nor enroll factors.
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2;`, signinTestTenant, user); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO authorization_subject_authorities VALUES($1,'users',$2,1) ON CONFLICT DO NOTHING`, signinTestTenant, user); err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second, HashPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := crypto.Hash(ctx, []byte("synthetic-reset-dummy"))
	if err != nil {
		t.Fatal(err)
	}
	signin, signinConfig := publicSigninFixture(t, pool, policy, crypto, dummy, sessionpg.Config{Schema: "signin_sessions", MaximumDuration: time.Second}, sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "signin-deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"})
	activeSession, err := resetTestSignin(t, ctx, pool, signin, signinConfig, canonical, []byte(" synthetic-signup-password "))
	if err != nil || activeSession.State != auth.SignInStateAuthenticated {
		t.Fatal("original reset-session login failed", err)
	}
	keys, err := keyring.New(map[string][]byte{"reset-output": bytes.Repeat([]byte{75}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("reset-test", bytes.Repeat([]byte{31}, 32))
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{31}, 32))
	resolver, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "reset-test", Verifier: verifier}})
	engine, err := capability.NewService(capability.ServiceConfig{Issuer: "https://identity.test", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := password.NewResetProfile(password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{"https://identity.test/reset"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {31}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"enrolled", "stale-factor", "expired-credential", "breached", "audit-rollback", "commit"} {
		t.Run("reset-"+mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user); err != nil {
				t.Fatal(err)
			}
			recipient, err := directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: signinTestTenant, UserID: identity.UserID(user), Kind: identity.IdentifierEmail, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
			if err != nil || recipient.Suppressed {
				t.Fatal("verified reset recipient unavailable", err)
			}
			var credential string
			if err := pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND kind=1`, signinTestTenant, user).Scan(&credential); err != nil {
				t.Fatal(err)
			}
			material, err := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: signinTestTenant, SubjectID: identity.UserID(user)})
			if err != nil {
				t.Fatal(err)
			}
			authority := material.Authority()
			originalHash := material.EncodedHash().String()
			id, _ := identity.NewCommandID()
			originID, _ := identity.NewCommandID()
			now := time.Now().UTC().Truncate(time.Second)
			origin := password.ResetGrantSpec{TenantID: signinTestTenant, UserID: identity.UserID(user), CredentialID: identity.CredentialID(credential), CredentialVersion: authority.Credential.Version, CredentialAuthorityVersion: recipient.CredentialAuthorityVersion, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierID: recipient.Identifier.ID, IdentifierVersion: recipient.Identifier.Version, FactorVersion: 1, OriginCommandID: originID, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: "https://identity.test/reset", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
			payload, err := profile.Payload(origin)
			if err != nil {
				t.Fatal(err)
			}
			payload.ID = string(originID)
			proof, _, err := engine.Issue(ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			grant, err := engine.Verify(ctx, proof, "identity.password.reset-complete", "reset")
			if err != nil {
				t.Fatal(err)
			}
			consumption := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: "identity.password.reset-complete", ReplayKeyVersion: 1, ReplayDigest: grant.EnvelopeDigest(), ProofFingerprint: grant.EnvelopeDigest(), ExpiresAt: origin.ExpiresAt, MaxUses: 1}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,1,$3,$4,$3,$5,1)`, signinTestTenant, string(consumption.Purpose), consumption.ReplayDigest[:], payload.ID, origin.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			i := kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{Credential: authority.Credential, ExpectedUserVersion: authority.User.Version, ExpectedAuthorityVersion: authority.AuthorityVersion}, ExpectedEnabled: authority.Enabled}
			b := identity.CommandBinding{CommandID: id, TenantID: signinTestTenant, UserID: identity.UserID(user), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: resetOperation().OperationID, SchemaID: resetOperation().SchemaID, SchemaVersion: 1, RecordID: credential, PolicyID: "reset", PolicyVersion: 1, CorrelationID: string(id)}
			fields, err := kernel.CredentialResetFields(i)
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := primitive.NewSecret([]byte(" synthetic-reset-password "))
			defer secret.Destroy()
			input, err := identity.NewFeaturePasswordResetInputCommand(identity.FeatureCommandSpec{Binding: b, Operation: resetOperation(), Fields: fields}, secret, proof)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := sessionpg.NewPasswordResetEffect(sessionpg.Config{Schema: "signin_sessions", MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			screeningPolicy := signupScreeningPolicy(t)
			calls := 0
			phase := &resetCompletionPhase{repository: repository, original: input, intent: i, profile: profile, origin: origin, grant: grant, consumption: consumption, recipient: recipient, sessions: effect, verifier: engine, crypto: sealer, envelopeKey: "reset-output", configuration: [32]byte{17}, riskConfig: signinTestRisk(t), subject: risk.Subject{Network: "192.0.2.1", Device: "synthetic-device", IdentifierDigest: strings.Repeat("a", 64)}, directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "signin-deployment", TenantID: signinTestTenant}, GlobalVersion: 1, TenantVersion: 1}, userAuthorization: kernel.UserAuthorizationAdmission{Scope: authoritypg.AuthorityScope{TenantID: signinTestTenant, SubjectID: authorization.SubjectID(user), PolicyNamespace: "users"}, Version: 1}}
			phase.screening = password.HashPreparationConfig{Primitive: crypto, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Policy: screeningPolicy, Now: time.Now, Collect: func(ctx context.Context, scope risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
				calls++
				observation := risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)}
				if mode == "breached" {
					observation.BreachCount = 1
				}
				fact, err := screeningPolicy.PasswordSignal(ctx, scope, observation)
				return []risk.Signal{fact}, err
			}}
			audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
			if err != nil {
				t.Fatal(err)
			}
			var auditOwner kernel.Contributor = audits
			if mode == "audit-rollback" {
				auditOwner = &resetFailingAudit{audits}
			}
			outbox, err := lifecyclepg.NewContributor()
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, auditOwner, outbox, phase, capabilitypg.NewParticipant()})
			if err != nil {
				t.Fatal(err)
			}
			queryPolicy := *signinConfig.Coordinator.QueryPolicy
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &queryPolicy})
			if err != nil {
				t.Fatal(err)
			}
			phase.coordinator = coordinator
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: credential}, Context: audit.ContextInput{TenantID: signinTestTenant, CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "credential", "aggregate.id": credential, "aggregate.before_version": strconv.FormatUint(i.Replacement.Credential.Version, 10), "aggregate.after_version": strconv.FormatUint(i.Replacement.Credential.Version+1, 10), "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, resetOperation(), "credential", seed)
			if err != nil {
				t.Fatal(err)
			}
			phase.declaration = kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: resetOperation()}, SubjectType: "credential", Capability: &consumption, Lifecycle: &kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: i.Replacement.Credential.Version, AfterVersion: i.Replacement.Credential.Version + 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
			plan, err := coordinator.PrepareFeaturePreparationPlan(input, phase.declaration)
			if err != nil {
				t.Fatal("reset preparation plan", err)
			}
			if mode == "enrolled" || mode == "stale-factor" {
				active := 0
				if mode == "enrolled" {
					active = 1
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=$3 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user, active); err != nil {
					t.Fatal(err)
				}
			}
			expectedAuthority := authority
			if mode == "expired-credential" {
				expiry := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=$3 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user, expiry); err != nil {
					t.Fatal(err)
				}
				expectedAuthority.ExpiresAt = expiry
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=NULL WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user); err != nil {
						t.Error(err)
					}
				}()
			}
			result, err := coordinator.ExecutePreparedFeature(ctx, input, plan)
			stored, readErr := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: signinTestTenant, SubjectID: identity.UserID(user)})
			if readErr != nil {
				t.Fatal(readErr)
			}
			var uses, receipts int
			if e := pool.Raw().QueryRow(ctx, `SELECT uses FROM capability_identity_one_use WHERE capability_id=$1`, payload.ID).Scan(&uses); e != nil {
				t.Fatal(e)
			}
			if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM signin_sessions.password_resets WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user).Scan(&receipts); e != nil {
				t.Fatal(e)
			}
			var sessionState string
			if e := pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.sessions WHERE tenant_id=$1 AND session_id=$2`, signinTestTenant, activeSession.SessionID).Scan(&sessionState); e != nil {
				t.Fatal(e)
			}
			if mode != "commit" {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted || stored.EncodedHash().String() != originalHash || stored.Authority() != expectedAuthority || uses != 0 || receipts != 0 || sessionState != "active" {
					t.Fatal("denied reset retained partial effects", err)
				}
				if (mode == "enrolled" || mode == "stale-factor" || mode == "expired-credential") && calls != 0 {
					t.Fatal("ineligible recovery reached password screening")
				}
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || stored.Authority().Credential.Version != authority.Credential.Version+1 || stored.Authority().AuthorityVersion != authority.AuthorityVersion+1 || uses != 1 || receipts != 1 || calls != 1 || sessionState != "revoked" {
				t.Fatal("native reset did not atomically commit", err)
			}
			match, e := crypto.Verify(ctx, []byte(" synthetic-reset-password "), stored.EncodedHash().String())
			if e != nil || !match.Match() {
				t.Fatal("new reset password unusable")
			}
			match, e = crypto.Verify(ctx, []byte(" synthetic-signup-password "), stored.EncodedHash().String())
			if !errors.Is(e, primitive.ErrMismatch) || match.Match() {
				t.Fatal("old password survived reset")
			}
			reader, ok := any(coordinator).(resetPreparationReader)
			if !ok {
				t.Fatal("caller-command reset retry cannot read its retained native output")
			}
			query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Action: authorization.Action(b.OperationID)}, PolicyRevision: authorization.Revision(queryPolicy.PolicyVersion)}
			output, generation, e := reader.QueryFeaturePreparation(ctx, query, caller, *plan.Feature, phase)
			if e != nil || generation != 1 || len(output) == 0 {
				t.Fatal("committed reset lost original output provenance", e)
			}
			defer clear(output)
			originalSpec, e := repository.readResetOutputIntent(ctx, sealer, b, generation, phase.configuration, output)
			if e != nil {
				t.Fatal("native retry cannot authenticate original reset intent", e)
			}
			originalIntent, e := passwordResetIntent(originalSpec)
			if e != nil || originalIntent != i || originalIntent.Replacement.ExpectedUserVersion == stored.Authority().User.Version {
				t.Fatal("retry substituted today's aggregate for original predecessor", e)
			}
			for _, change := range []func(*identity.RecoveryQuery, *authorization.DecisionContext){
				func(q *identity.RecoveryQuery, c *authorization.DecisionContext) {
					q.UserID = "foreign"
					c.Request.Resource.ID = "foreign"
				},
				func(q *identity.RecoveryQuery, c *authorization.DecisionContext) { q.RecordID = "foreign" },
				func(q *identity.RecoveryQuery, c *authorization.DecisionContext) { c.Request.Subject.ID = "foreign" },
			} {
				q, c := query, caller.Clone()
				change(&q, &c)
				wire, g, e := reader.QueryFeaturePreparation(ctx, q, c, *plan.Feature, phase)
				if e == nil || len(wire) != 0 || g != 0 {
					t.Fatal("foreign reset query disclosed retained output")
				}
			}
			foreignOwner := &resetCompletionPhase{}
			if wire, g, e := reader.QueryFeaturePreparation(ctx, query, caller, *plan.Feature, foreignOwner); e == nil || len(wire) != 0 || g != 0 {
				t.Fatal("descriptor spoof read original reset output")
			}
			rebuilt, e := identity.NewFeaturePasswordResetInputCommand(originalSpec, secret, proof)
			if e != nil {
				t.Fatal(e)
			}
			phase.original = rebuilt
			replay, e := coordinator.ExecutePreparedFeature(ctx, rebuilt, plan)
			if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || calls != 1 {
				t.Fatal("reset replay regenerated effects", e)
			}
			changedSecret, _ := primitive.NewSecret([]byte("synthetic-changed-reset-password"))
			defer changedSecret.Destroy()
			changed, e := identity.NewFeaturePasswordResetInputCommand(originalSpec, changedSecret, proof)
			if e != nil {
				t.Fatal(e)
			}
			phase.original = changed
			conflict, e := coordinator.ExecutePreparedFeature(ctx, changed, plan)
			var collision identity.ConflictError
			if !errors.As(e, &collision) || conflict.Outcome == identity.CommitOutcomeCommitted || calls != 1 {
				t.Fatal("retained output bypassed original raw password conflict", e)
			}
			changedPayload := payload
			changedPayload.ID = "synthetic-foreign-reset-proof"
			changedProof, _, e := engine.Issue(ctx, changedPayload)
			if e != nil {
				t.Fatal(e)
			}
			defer changedProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			changed, e = identity.NewFeaturePasswordResetInputCommand(originalSpec, secret, changedProof)
			if e != nil {
				t.Fatal(e)
			}
			phase.original = changed
			conflict, e = coordinator.ExecutePreparedFeature(ctx, changed, plan)
			if !errors.As(e, &collision) || conflict.Outcome == identity.CommitOutcomeCommitted || calls != 1 {
				t.Fatal("retained output bypassed original proof-byte conflict", e)
			}
			phase.original = rebuilt
			oldLogin, e := resetTestSignin(t, ctx, pool, signin, signinConfig, canonical, []byte(" synthetic-signup-password "))
			if e != nil || oldLogin.State != auth.SignInStateRejected || oldLogin.Issuance.Token != (session.Token{}) || oldLogin.SessionID != "" {
				t.Fatal("old password admitted public signin")
			}
			newLogin, e := resetTestSignin(t, ctx, pool, signin, signinConfig, canonical, []byte(" synthetic-reset-password "))
			if e != nil || newLogin.State != auth.SignInStateAuthenticated || newLogin.SessionID == activeSession.SessionID {
				t.Fatal("new password cannot create successor login", e)
			}
		})
	}
	t.Run("public reset completion", func(t *testing.T) {
		testPublicResetCompletion(t, ctx, pool, directory, policy, crypto, signin, signinConfig, user, canonical)
	})
}

func resetTestSignin(t *testing.T, ctx context.Context, pool *database.Pool, service *SigninService, c SigninConfig, canonical string, raw []byte) (password.SigninResult, error) {
	t.Helper()
	r, _, _, _ := nativeSigninFlow(t)
	r.Password.Destroy()
	r.Password, _ = primitive.NewSecret(raw)
	defer r.Password.Destroy()
	r.TenantID, r.Caller.Request.Tenant, r.Caller.Request.Subject.ID = signinTestTenant, signinTestTenant, signinTestActor
	r.Identifier, r.Device = identifier.Input(canonical), "synthetic-device"
	r.PreAuthID, _ = identity.NewPreAuthTransactionID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{2}, Remember: r.Remember, PolicyID: c.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	token, _ := session.ParseToken(r.Cookie.Token())
	digest, err := token.PreAuthDigest(c.FlowKeys[0], b)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, c.Session, flow); err != nil {
		t.Fatal(err)
	}
	return service.Signin(ctx, r)
}
