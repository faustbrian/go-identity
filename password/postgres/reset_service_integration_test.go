//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This explicit request fixture only invokes real durable issuance/factor
// owners. Public request enumeration/risk/delivery are not supplied by it.
type resetServiceIssuanceFixture struct {
	command       identity.Command
	recipient     kernel.RecipientRecord
	credential    kernel.CredentialAdmission
	issuer        *issuerpg.Issuer
	prepared      issuerpg.PreparedIssuance
	deliveryOwner *deliverypg.Contributor
	delivery      deliverypg.PreparedDelivery
	failed        string
}

func (*resetServiceIssuanceFixture) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *resetServiceIssuanceFixture) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *resetServiceIssuanceFixture) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *resetServiceIssuanceFixture) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, err := w.RequireResetRecipientCredential(ctx, p, p.recipient, p.credential, true); err != nil {
		p.failed = "recipient"
		return identity.FeatureReceipt{}, err
	}
	if _, err := mfapg.RequireEmailRecovery(ctx, w, p, c, p.recipient.User.ID, 1); err != nil {
		p.failed = "factor"
		return identity.FeatureReceipt{}, err
	}
	if err := p.issuer.Stage(ctx, w, p.prepared); err != nil {
		p.failed = "issuance"
		return identity.FeatureReceipt{}, err
	}
	if p.deliveryOwner != nil {
		if err := p.deliveryOwner.Stage(ctx, w, p.delivery); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (*resetServiceIssuanceFixture) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func testPublicResetCompletion(t *testing.T, ctx context.Context, pool *database.Pool, directory *kernel.Repository, policy primitive.Policy, crypto *primitive.Service, signin *SigninService, signinConfig SigninConfig, user, canonical string) {
	var deliveryInstalled bool
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.delivery_intents') IS NOT NULL`).Scan(&deliveryInstalled); err != nil {
		t.Fatal(err)
	}
	if !deliveryInstalled {
		history, err := (deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 20}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if m.Version() == 20 {
				if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	wire, err := fs.ReadFile(issuerpg.Migrations(), "002_original_issuance.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("public-reset", bytes.Repeat([]byte{93}, 32))
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{93}, 32))
	resolver, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "public-reset", Verifier: verifier}})
	issuerConfig := issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.test", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "reset", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {94}}, PreparationTimeout: time.Second}
	issuer, err := issuerpg.NewIssuer(issuerConfig)
	if err != nil {
		t.Fatal(err)
	}
	profileConfig := password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{"https://identity.test/reset"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {95}}}
	profile, err := password.NewResetProfile(profileConfig)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second, HashPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: signinTestTenant, Kind: identity.IdentifierEmail, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
	if err != nil || recipient.Suppressed {
		t.Fatal("original public reset recipient", err)
	}
	material, err := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: signinTestTenant, SubjectID: identity.UserID(user)})
	if err != nil {
		t.Fatal(err)
	}
	authority := material.Authority()
	id, _ := identity.NewCommandID()
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	b := identity.CommandBinding{CommandID: id, TenantID: signinTestTenant, AnonymousFlowID: string(id), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "reset", PolicyVersion: 3, CorrelationID: string(id)}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "fixture", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	origin := password.ResetGrantSpec{TenantID: b.TenantID, UserID: identity.UserID(user), CredentialID: authority.Credential.ID, CredentialVersion: authority.Credential.Version, CredentialAuthorityVersion: authority.AuthorityVersion, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierID: recipient.Identifier.ID, IdentifierVersion: recipient.Identifier.Version, FactorVersion: 1, OriginCommandID: id, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: "https://identity.test/reset", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	payload, err := profile.Payload(origin)
	if err != nil {
		t.Fatal(err)
	}
	var artifacts resetRequestDelivery
	var deliveryConfig resetRequestDeliveryPreparation
	t.Run("encrypted reset request preparation", func(t *testing.T) {
		artifacts, deliveryConfig = testResetRequestDelivery(t, ctx, repository, issuer, profile, b, origin, recipient, resolver)
	})
	prepared := artifacts.issuance
	phase := &resetServiceIssuanceFixture{command: command, recipient: recipient, credential: kernel.CredentialAdmission{Credential: authority.Credential, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierAuthorityVersion: recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: recipient.CredentialAuthorityVersion}, issuer: issuer, prepared: prepared, deliveryOwner: deliveryConfig.owner, delivery: artifacts.delivery}
	audits, _ := auditpg.NewIdentityContributor(auditpg.Config{})
	outbox, _ := lifecyclepg.NewContributor()
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, audits, outbox, phase, issuer, deliveryConfig.owner})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, signinConfig.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	issue, _ := prepared.Plan()
	declaration, err := resetServiceAuditDeclaration(b, op, registry.Descriptors(), "user", 0, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	declaration.CapabilityIssuance = &issue
	deliveryPlan, err := artifacts.delivery.Plan()
	if err != nil {
		t.Fatal(err)
	}
	declaration.Delivery = &deliveryPlan
	declaration.Lifecycle.EventType = "password.reset.requested.v1"
	plan, err := coordinator.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := coordinator.Begin(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Abort(w, identity.UnavailableError{})
	result, err := coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		t.Fatal("fixture admission", phase.failed, err)
	}
	if result, err = coordinator.Commit(w, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real issuer request fixture", err)
	}
	mailKeys, _ := keyring.New(map[string][]byte{"reset-mail": bytes.Repeat([]byte{102}, 32)})
	mailCrypto, _ := envelope.NewService(mailKeys)
	proof := captureResetDelivery(t, ctx, pool, deliveryConfig, signinConfig.Coordinator, canonical, mailCrypto)
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	dummy, _ := crypto.Hash(ctx, []byte("synthetic-reset-dummy"))
	screeningPolicy := signupScreeningPolicy(t)
	calls := 0
	screening := password.HashPreparationConfig{Primitive: crypto, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Policy: screeningPolicy, Now: time.Now, Collect: func(ctx context.Context, c risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
		calls++
		f, e := screeningPolicy.PasswordSignal(ctx, c, risk.PasswordObservation{ObservedAt: c.Now, CheckedAt: c.Now, ValidUntil: c.Now.Add(time.Hour)})
		return []risk.Signal{f}, e
	}}
	keys, _ := keyring.New(map[string][]byte{"reset-output": bytes.Repeat([]byte{96}, 32)})
	service, err := NewResetService(pool, ResetConfig{Repository: Config{MaximumDuration: 3 * time.Second, HashPolicy: policy}, ConfigurationID: "reset-test-v1", PolicyID: "reset", Profile: profileConfig, Issuer: issuerConfig, Screening: screening, Risk: signinTestRisk(t), Coordinator: signinConfig.Coordinator, Session: signinConfig.Session, GlobalAuthorityID: "signin-deployment", AuthorizationNamespace: "users", Origins: []string{"https://identity.test"}, ActiveEnvelopeKeyID: "reset-output", IdentifierKey: [32]byte{97}}, keys)
	if err != nil {
		t.Fatal("public reset startup", err)
	}
	id, _ = identity.NewCommandID()
	secret, _ := primitive.NewSecret([]byte("synthetic-public-reset-password"))
	defer secret.Destroy()
	caller := authorization.DecisionContext{Request: authorization.Request{Tenant: signinTestTenant, Subject: authorization.Subject{ID: signinTestActor, Kind: authorization.SubjectServiceAccount}, Action: "identity.password.reset-complete", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}, Environment: authorization.Environment{Time: time.Now().UTC()}}, PolicyRevision: 3, CorrelationID: string(id)}
	request := password.ResetCompleteRequest{TenantID: signinTestTenant, CommandID: id, Token: proof, NewPassword: secret, Caller: caller, Origin: "https://identity.test", Network: "192.0.2.1", Device: "synthetic-device"}
	inspect := func(r password.ResetCompleteRequest) (password.ResetInspectResult, error) {
		c := r.Caller.Clone()
		c.Request.Action = "identity.password.reset-inspect"
		return service.ResetInspect(ctx, password.ResetInspectRequest{TenantID: r.TenantID, Token: r.Token, Caller: c, Origin: r.Origin})
	}
	for range 2 {
		if result, err := inspect(request); err != nil || !result.Valid || calls != 0 || proof.ValidateBounds(32, 4096) != nil {
			t.Fatal("native repeated inspection consumed proof or reached password work")
		}
	}
	t.Run("expired inspection", func(t *testing.T) {
		originalIssuer := service.issuer
		future := issuerConfig
		future.Crypto.Clock = func() time.Time { return origin.ExpiresAt }
		service.issuer, err = issuerpg.NewIssuer(future)
		if err != nil {
			t.Fatal("expired-clock issuer configuration rejected")
		}
		defer func() { service.issuer = originalIssuer }()
		if result, err := inspect(request); err != nil || result.Valid || calls != 0 {
			t.Fatal("expired original proof retained positive inspection")
		}
	})
	t.Run("cancelled inspection", func(t *testing.T) {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		c := caller.Clone()
		c.Request.Action = "identity.password.reset-inspect"
		result, err := service.ResetInspect(cancelled, password.ResetInspectRequest{TenantID: request.TenantID, Token: proof, Caller: c, Origin: request.Origin})
		if !errors.Is(err, context.Canceled) || result.Valid || calls != 0 {
			t.Fatal("cancelled inspection returned positive state or performed password work")
		}
	})
	for _, mode := range []string{"foreign-origin", "foreign-target", "foreign-tenant", "unissued", "enrolled", "audit-rollback"} {
		t.Run(mode, func(t *testing.T) {
			denied := request
			denied.Caller = request.Caller.Clone()
			denied.CommandID, _ = identity.NewCommandID()
			denied.Caller.CorrelationID = string(denied.CommandID)
			issued, _ := prepared.Plan()
			switch mode {
			case "foreign-origin":
				denied.Origin = "https://foreign.test"
			case "foreign-target":
				denied.Caller.Request.Resource.ID = "foreign-user"
			case "foreign-tenant":
				denied.TenantID = "foreign-tenant"
				denied.Caller.Request.Tenant = "foreign-tenant"
			case "unissued":
				engine, e := capability.NewService(issuerConfig.Crypto)
				if e != nil {
					t.Fatal(e)
				}
				foreign := payload
				foreign.ID = "synthetic-unissued-public-reset"
				denied.Token, _, e = engine.Issue(ctx, foreign)
				if e != nil {
					t.Fatal(e)
				}
				defer denied.Token.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			case "enrolled":
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, user); e != nil {
						t.Error(e)
					}
				}()
			case "audit-rollback":
				// A terminal release deliberately burns the failed command's
				// evidence. Give this rollback case its own real issued grant.
				freshBinding := b
				freshBinding.CommandID, _ = identity.NewCommandID()
				freshBinding.AnonymousFlowID = string(freshBinding.CommandID)
				freshBinding.CorrelationID = string(freshBinding.CommandID)
				freshOrigin := origin
				freshOrigin.OriginCommandID = freshBinding.CommandID
				freshPayload, e := profile.Payload(freshOrigin)
				if e != nil {
					t.Fatal(e)
				}
				freshPrepared, e := issuer.PrepareResetRecipient(ctx, freshBinding, identity.UserID(user), freshPayload)
				if e != nil {
					t.Fatal(e)
				}
				freshCommand, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: freshBinding, Operation: op, Fields: []identity.FeatureField{{Name: "fixture", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}})
				if e != nil {
					t.Fatal(e)
				}
				phase.command, phase.prepared = freshCommand, freshPrepared
				phase.deliveryOwner = nil
				freshIssue, _ := freshPrepared.Plan()
				issued = freshIssue
				freshDeclaration, e := resetServiceAuditDeclaration(freshBinding, op, registry.Descriptors(), "user", 0, 0, now)
				if e != nil {
					t.Fatal(e)
				}
				freshDeclaration.CapabilityIssuance = &freshIssue
				freshDeclaration.Contributors = freshDeclaration.Contributors[:len(freshDeclaration.Contributors)-1]
				freshDeclaration.Lifecycle.EventType = "password.reset.requested.v1"
				freshPlan, e := coordinator.PrepareCommandPlan(freshBinding, freshCommand, freshDeclaration)
				if e != nil {
					t.Fatal(e)
				}
				reservation, _, e := coordinator.ReserveCommand(ctx, freshBinding, freshCommand, freshPlan)
				if e != nil {
					t.Fatal(e)
				}
				work, e := coordinator.Begin(ctx, reservation)
				if e != nil {
					t.Fatal(e)
				}
				defer coordinator.Abort(work, identity.UnavailableError{})
				issuedResult, e := coordinator.ApplyFeature(ctx, work, freshCommand)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = coordinator.Commit(work, issuedResult); e != nil {
					t.Fatal(e)
				}
				if e = freshPrepared.TransferForDelivery(ctx, 0, func(_ context.Context, raw []byte) error {
					denied.Token, e = capability.ParseProof(string(raw), capability.DefaultLimits())
					return e
				}); e != nil {
					t.Fatal(e)
				}
				defer denied.Token.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
				if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT reset_public_failure CHECK(false) NOT VALID`); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT IF EXISTS reset_public_failure`); e != nil {
						t.Error(e)
					}
				}()
			}
			before := calls
			inspected, inspectionErr := inspect(denied)
			if calls != before || mode != "audit-rollback" && inspected.Valid || mode == "audit-rollback" && (inspectionErr != nil || !inspected.Valid) {
				t.Fatal("native inspection accepted ineligible authority or performed password work")
			}
			result, e := service.ResetComplete(ctx, denied)
			if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("public reset denial committed", e)
			}
			if mode != "audit-rollback" && calls != before {
				t.Fatal("ineligible public reset reached password screening")
			}
			unchanged, e := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: signinTestTenant, SubjectID: identity.UserID(user)})
			if e != nil || unchanged.Authority() != authority || unchanged.EncodedHash().String() != material.EncodedHash().String() {
				t.Fatal("public reset denial changed credential", e)
			}
			var uses int
			if e := pool.Raw().QueryRow(ctx, `SELECT uses FROM capability_identity_one_use WHERE capability_id=$1`, issued.Grants[0].CapabilityID).Scan(&uses); e != nil || uses != 0 {
				t.Fatal("public reset denial consumed issued proof", e)
			}
			if mode == "audit-rollback" {
				if _, e := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT reset_public_failure`); e != nil {
					t.Fatal(e)
				}
				key, _ := base64.RawURLEncoding.DecodeString(string(denied.CommandID))
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
					t.Fatal(e)
				}
				q := identity.RecoveryQuery{CommandID: denied.CommandID, TenantID: signinTestTenant, UserID: identity.UserID(user), ActorID: identity.ActorID(signinTestActor), ActorKind: authorization.SubjectServiceAccount, OperationID: resetOperation().OperationID, RecordID: string(authority.Credential.ID)}
				recovered, e := service.RecoverResetComplete(ctx, q, denied.Caller)
				// Recovery closes a proven rollback while retaining the original
				// dependency-failure classification; that error is not ambiguity.
				var dependency identity.UnavailableError
				if !errors.As(e, &dependency) || recovered.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("public reset ambiguous rollback cannot reconcile original effects", e)
				}
				var state string
				if e := pool.Raw().QueryRow(ctx, `SELECT state,uses FROM capability_identity_one_use WHERE capability_id=$1`, issued.Grants[0].CapabilityID).Scan(&state, &uses); e != nil || state != "released" || uses != 0 {
					t.Fatal("reconciled rollback did not terminal-release original proof", e)
				}
			}
		})
	}
	callsBefore := calls
	completed, err := service.ResetComplete(ctx, request)
	if err != nil || completed.Validate() != nil || completed.Outcome != identity.CommitOutcomeCommitted || completed.CredentialVersion != authority.Credential.Version+1 || !completed.SessionsRevoked || calls != callsBefore+1 {
		t.Fatal("public reset did not commit all effects", err)
	}
	if again, err := service.ResetComplete(ctx, request); err != nil || again != completed || calls != callsBefore+1 {
		t.Fatal("public reset replay changed receipt or regenerated", err)
	}
	if result, err := inspect(request); err != nil || result.Valid || calls != callsBefore+1 {
		t.Fatal("consumed reset proof retained positive inspection or repeated password work")
	}
	changed, _ := primitive.NewSecret([]byte("synthetic-conflicting-public-reset"))
	defer changed.Destroy()
	other := request
	other.NewPassword = changed
	var collision identity.ConflictError
	if changed, err := service.ResetComplete(ctx, other); !errors.As(err, &collision) || changed.Outcome == identity.CommitOutcomeCommitted || calls != callsBefore+1 {
		t.Fatal("public reset retry ignored changed password", err)
	}
	q := identity.RecoveryQuery{CommandID: id, TenantID: signinTestTenant, UserID: identity.UserID(user), ActorID: identity.ActorID(signinTestActor), ActorKind: authorization.SubjectServiceAccount, OperationID: resetOperation().OperationID, RecordID: string(authority.Credential.ID)}
	if recovered, err := service.RecoverResetComplete(ctx, q, caller); err != nil || recovered != completed || calls != callsBefore+1 {
		t.Fatal("proof-free public reset recovery", err)
	}
	oldLogin, err := resetTestSignin(t, ctx, pool, signin, signinConfig, canonical, []byte(" synthetic-reset-password "))
	if err != nil || oldLogin.State != auth.SignInStateRejected {
		t.Fatal("replaced password public login accepted", err)
	}
	newLogin, err := resetTestSignin(t, ctx, pool, signin, signinConfig, canonical, []byte("synthetic-public-reset-password"))
	if err != nil || newLogin.State != auth.SignInStateAuthenticated {
		t.Fatal("new public reset password cannot login", err)
	}
	t.Run("public reset request", func(t *testing.T) {
		testPublicResetRequest(t, ctx, service, keys, deliveryConfig, canonical, signin, signinConfig)
	})
}
