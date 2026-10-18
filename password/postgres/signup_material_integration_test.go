//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type signupMaterialWriter interface {
	applySignupMaterial(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command, kernel.PasswordRegistrationIntent) error
}

// This fixture owns only invocation wiring; all account/reference and actual
// verifier writes use the production owners in the same coordinator Work.
type signupMaterialPhase struct {
	repository        *Repository
	domain            *kernel.PasswordRegistrationDomain
	command           identity.Command
	intent            kernel.PasswordRegistrationIntent
	rollback          bool
	materialAttempted bool
	skipDomain        bool
	duplicate         bool
	foreign           bool
	accept            bool
	accepted          bool
	materialSucceeded bool
	request           *password.SignupRequest
	flow              session.PreAuthTransaction
	flowKey           session.DigestKey
	flowConfig        sessionpg.Config
}

func (*signupMaterialPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *signupMaterialPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.PasswordSignupFeature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *signupMaterialPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	_, err := p.repository.signupMaterial(c, p.intent)
	return err
}
func (p *signupMaterialPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.request != nil {
		if err := p.repository.applySignupPreAuth(ctx, w, p, c, *p.request, p.flow, p.flowKey, p.flowConfig); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if !p.skipDomain {
		var err error
		if p.accept {
			_, p.accepted, err = p.domain.ApplyOrAccept(ctx, w, p, c, p.intent)
		} else {
			_, err = p.domain.Apply(ctx, w, p, c, p.intent)
		}
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.materialAttempted = true
	writer, ok := any(p.repository).(signupMaterialWriter)
	if !ok {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if p.foreign {
		s, _ := c.PasswordSignupFeature()
		hash, cookie, _ := c.PasswordSignupCustody()
		c, _ = identity.NewFeaturePasswordSignupCommand(s, hash, cookie)
	}
	err := writer.applySignupMaterial(ctx, w, p, c, p.intent)
	p.materialSucceeded = err == nil
	if p.accepted {
		if err != password.ErrPasswordWork {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		s, _ := c.PasswordSignupFeature()
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.duplicate {
		if err := writer.applySignupMaterial(ctx, w, p, c, p.intent); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.rollback {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.PasswordSignupFeature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (*signupMaterialPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, password.ErrPasswordWork
}

func (p *signupMaterialPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	if p.request == nil {
		return nil
	}
	return p.repository.checkSignupPreAuthCommit(ctx, w, p, c, *p.request, p.flow, p.flowKey)
}

func testNativeSignupMaterial(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, crypto *primitive.Service, base kernel.DirectoryAuthorityMigrationSource) {
	t.Helper()
	history, err := (kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.PasswordRegistrationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: base, Version: 14}, Version: 15}, Version: 16}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() >= 14 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("registration install", err)
			}
		}
	}
	schema := identity.AttributeSchema{ID: "signup-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSelf, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1}}}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewPasswordRegistrationDomain(directory, kernel.PasswordRegistrationDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second, HashPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	var committedFlow session.PreAuthTransaction
	for _, mode := range []string{"commit", "native-first-account", "native-second-account", "rollback", "missing-domain", "duplicate", "foreign-command", "existing-domain", "neutral", "flow-commit", "flow-replay", "flow-rollback", "flow-neutral", "flow-cookie", "flow-actor", "flow-expired", "flow-expired-audit"} {
		t.Run(mode, func(t *testing.T) {
			nativeCreation := strings.HasPrefix(mode, "native-")
			if nativeCreation {
				mode = "commit"
			}
			useFlow := strings.HasPrefix(mode, "flow-")
			mode = strings.TrimPrefix(mode, "flow-")
			id, _ := identity.NewCommandID()
			user, _ := identity.NewSubjectID()
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
			b := identity.CommandBinding{CommandID: id, TenantID: signinTestTenant, UserID: identity.UserID(user), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "signup", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: string(id)}
			var request password.SignupRequest
			var flow session.PreAuthTransaction
			var flowKey session.DigestKey
			flowConfig := sessionpg.Config{Schema: "signin_sessions", MaximumDuration: time.Second}
			cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			if useFlow {
				request, flow, flowKey, _ = nativeSignupFlow(t)
				s, _ := flow.Bindings()
				s.Binding.ID, _ = identity.NewPreAuthTransactionID()
				s.Binding.Intent.TenantID = b.TenantID
				s.Binding.Intent.PolicyID, s.Binding.Intent.PolicyVersion = b.PolicyID, b.PolicyVersion
				s.Binding.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
				s.Binding.ExpiresAt = s.Binding.IssuedAt.Add(5 * time.Minute)
				if mode == "expired-audit" {
					s.Binding.IssuedAt = s.Binding.IssuedAt.Add(-59 * time.Second)
					s.Binding.ExpiresAt = s.Binding.IssuedAt.Add(time.Minute)
				}
				if mode == "expired" {
					s.Binding.IssuedAt = s.Binding.IssuedAt.Add(-61 * time.Second)
					s.Binding.ExpiresAt = s.Binding.IssuedAt.Add(time.Minute)
				}
				if mode == "replay" {
					var originalErr error
					s, originalErr = committedFlow.Bindings()
					if originalErr != nil {
						t.Fatal("missing previously committed signup flow")
					}
				}
				request.TenantID, request.PreAuthID = b.TenantID, s.Binding.ID
				request.Caller.Request.Tenant, request.Caller.Request.Subject.ID = authorization.TenantID(b.TenantID), authorization.SubjectID(b.ActorID)
				token, _ := session.ParseToken(request.Cookie.Token())
				s.Cookie, _ = token.PreAuthDigest(flowKey, s.Binding)
				flow, err = session.NewPreAuthTransaction(s)
				if err != nil || mode != "replay" && sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, flowConfig, flow) != nil {
					t.Fatal("signup flow fixture")
				}
				b.UserID, b.AnonymousFlowID = "", string(request.PreAuthID)
				op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
				cookie = request.Cookie
			}
			creation := b
			creation.UserID, creation.AnonymousFlowID = identity.UserID(user), ""
			creation.OperationID = "identity.user.create"
			creation.SchemaID = schema.ID
			intent := kernel.PasswordRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Identifier: identity.Identifier{ID: identity.IdentifierID(user), UserID: creation.UserID, Kind: identity.IdentifierEmail, CanonicalValue: string(user) + "@example.test", Version: 1}, Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: creation.UserID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
			if nativeCreation {
				// Two real registrations in one tenant exercise the native selected
				// identifier, not a hand-built intent which hides ID collisions.
				r, _, _, _ := nativeSignupFlow(t)
				r.IdempotencyKey, _ = identity.NewIdempotencyKey(bytes.Repeat([]byte{'N'}, 32))
				r.TenantID, r.Caller.Request.Tenant = b.TenantID, authorization.TenantID(b.TenantID)
				r.Caller.Request.Subject.ID, r.Caller.Request.Subject.Kind = authorization.SubjectID(b.ActorID), b.ActorKind
				r.Email = password.SignupAddressInput(string(user) + "@example.test")
				b.UserID, b.AnonymousFlowID = "", string(r.PreAuthID)
				op = passwordSignupOperation()
				processor, processorErr := identity.NewAttributeProcessor(schema, signinPublicPolicy{}, func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
					return s, nil
				}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: b.PolicyVersion, ValidateCanonicalUserID: func(_ context.Context, selected identity.UserID) error {
					if selected != identity.UserID(user) {
						return password.ErrPasswordWork
					}
					return nil
				}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }})
				if processorErr != nil {
					t.Fatal(processorErr)
				}
				profile, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "signup-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
				address, addressErr := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: profile, PreserveDisplay: true})
				if addressErr != nil {
					t.Fatal(addressErr)
				}
				intent, err = repository.prepareSignupCreation(ctx, r, b, identity.UserID(user), processor, address, schema.ID, schema.Version, "email-v1", nil)
				if err != nil {
					t.Fatal("native selected account preparation", err)
				}
				cookie = r.Cookie
			}
			var existing identity.UserID
			if mode == "existing-domain" || mode == "neutral" {
				existing = b.UserID
				identifier := intent.Identifier.ID
				if mode == "neutral" {
					old, _ := identity.NewSubjectID()
					existing, identifier = identity.UserID(old), identity.IdentifierID(old)
					if !useFlow {
						flow, _ := identity.NewPreAuthTransactionID()
						b.UserID, b.AnonymousFlowID = "", string(flow)
					}
					op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
				}
				for _, query := range []struct {
					sql  string
					args []any
				}{
					{`INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, []any{string(b.TenantID), string(existing)}},
					{`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, []any{string(b.TenantID), string(existing)}},
					{`INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version) VALUES($1,$2,$3,'email',$4,false,false,1,1,1)`, []any{string(b.TenantID), string(existing), string(identifier), intent.Identifier.CanonicalValue}},
				} {
					if _, err := pool.Raw().Exec(ctx, query.sql, query.args...); err != nil {
						t.Fatal("existing account fixture", err)
					}
				}
			}
			fields, err := kernel.PasswordRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := crypto.Hash(ctx, []byte(" synthetic-signup-password "))
			if err != nil {
				t.Fatal("synthetic hashing")
			}
			command, err := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, hash.String(), cookie)
			if err != nil {
				t.Fatal(err)
			}
			phase := &signupMaterialPhase{repository: repository, domain: domain, command: command, intent: intent, rollback: mode == "rollback", skipDomain: mode == "missing-domain" || mode == "existing-domain", duplicate: mode == "duplicate", foreign: mode == "foreign-command", accept: mode == "neutral"}
			if useFlow {
				if mode == "cookie" {
					request.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{101}, 32)))
				}
				if mode == "actor" {
					request.Caller.Request.Subject.ID = "foreign"
				}
				phase.request, phase.flow, phase.flowKey, phase.flowConfig = &request, flow, flowKey, flowConfig
			}
			audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
			if err != nil {
				t.Fatal(err)
			}
			outbox, err := lifecyclepg.NewContributor()
			if err != nil {
				t.Fatal(err)
			}
			var auditOwner kernel.Contributor = audits
			if mode == "expired-audit" {
				s, _ := flow.Bindings()
				auditOwner = &signinDelayedAudit{IdentityContributor: audits, until: s.Binding.ExpiresAt.Add(10 * time.Millisecond)}
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, auditOwner, outbox, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			target := string(b.UserID)
			if target == "" {
				target = b.AnonymousFlowID
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "user", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "user", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{SignupAcceptance: mode == "neutral", Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "user", Lifecycle: &kernel.LifecyclePlan{EventType: "user.created.v1"}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("reserve signup", err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("begin signup", err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, err = coordinator.ApplyFeature(ctx, work, command)
			if err != nil {
				result, err = coordinator.Abort(work, err)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			if (mode == "commit" || mode == "neutral") && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				if !phase.materialAttempted {
					t.Fatal("registration fixture failed before native material execution")
				}
				t.Fatal("native signup did not atomically commit usable material", err)
			}
			if mode != "commit" && mode != "neutral" && (err == nil || result.Outcome != identity.CommitOutcomeNotCommitted) {
				t.Fatal("native signup failure did not roll back")
			}
			if useFlow {
				var state string
				if err := pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), string(request.PreAuthID)).Scan(&state); err != nil {
					t.Fatal("signup flow state")
				}
				want := "issued"
				if mode == "commit" || mode == "neutral" || mode == "replay" {
					want = "consumed"
				}
				if state != want {
					t.Fatal("signup flow and account outcome diverged")
				}
				if mode == "commit" {
					committedFlow = flow
				}
			}
			stored, readErr := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: b.TenantID, SubjectID: intent.Creation.Binding.UserID})
			var factorRows int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 AND version=1 AND active_factors=0`, string(b.TenantID), string(intent.Creation.Binding.UserID)).Scan(&factorRows); err != nil {
				t.Fatal("factor authority read", err)
			}
			wantFactorRows := 0
			if mode == "commit" {
				wantFactorRows = 1
			}
			if factorRows != wantFactorRows {
				t.Fatal("fresh account factor authority did not follow atomic signup outcome")
			}
			if mode != "commit" {
				if readErr != password.ErrCredentialAbsent {
					t.Fatal("rolled-back signup retained material")
				}
				if (mode == "neutral" || mode == "existing-domain") && phase.materialSucceeded {
					t.Fatal("existing or neutral account acquired material")
				}
				var count int
				want := 0
				if mode == "existing-domain" {
					want = 1
				}
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(intent.Creation.Binding.UserID)).Scan(&count); err != nil || count != want {
					t.Fatal("failed signup retained provisional account")
				}
				if existing != "" {
					if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users u JOIN identity.credential_references c USING(tenant_id,user_id) JOIN identity.identifiers i USING(tenant_id,user_id) WHERE u.tenant_id=$1 AND u.user_id=$2 AND u.status='active' AND u.version=1 AND c.version=1 AND c.enabled AND i.version=1 AND NOT i.verified AND NOT EXISTS(SELECT 1 FROM identity_password.credentials p WHERE p.tenant_id=u.tenant_id AND p.user_id=u.user_id)`, string(b.TenantID), string(existing)).Scan(&count); err != nil || count != 1 {
						t.Fatal("preexisting account changed")
					}
				}
				return
			}
			if readErr != nil || stored.EncodedHash().String() != hash.String() || stored.Authority().Credential.Version != 1 {
				t.Fatal("committed original verifier unavailable")
			}
			matched, verifyErr := crypto.Verify(ctx, []byte(" synthetic-signup-password "), stored.EncodedHash().String())
			if verifyErr != nil || !matched.Match() {
				t.Fatal("committed signup password unusable")
			}
		})
	}
	testResetFactorAuthority(t, ctx, pool, directory)
	t.Run("native reset completion", func(t *testing.T) {
		testNativeResetCompletion(t, ctx, pool, directory, policy, crypto, base)
	})
}
