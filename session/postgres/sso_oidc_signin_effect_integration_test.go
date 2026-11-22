//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Organization/postgres already consumes session/postgres. This explicit
// SQL-backed port avoids a reverse module edge while retaining membership and
// epoch checks in the same Work. It is not the real organization's public owner.
type ssoOIDCSessionOrganizationFixture struct{ pool *database.Pool }

// Reuse the real test SQL audit adapter, but fail only its successful attempt.
// The coordinator can then persist the required failure audit and release grant
// custody instead of correctly retaining an Unknown outcome during audit outage.
type ssoOIDCSessionSuccessAuditFailure struct{ revokeAudit }

func (p *ssoOIDCSessionSuccessAuditFailure) PersistAudits(ctx context.Context, w kernel.Work) error {
	if err := p.revokeAudit.PersistAudits(ctx, w); err != nil {
		return err
	}
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Record.Outcome() == audit.OutcomeSucceeded {
			return identity.UnavailableError{}
		}
	}
	return nil
}

func (p *ssoOIDCSessionOrganizationFixture) ObserveOrganizationSession(ctx context.Context, record session.Session) (OrganizationSessionAuthorityObservation, error) {
	spec, err := record.Bindings()
	if err != nil {
		return OrganizationSessionAuthorityObservation{}, err
	}
	vector, _ := spec.Authority.Bindings()
	start := time.Now().UTC()
	var key string
	var version uint64
	var active bool
	err = p.pool.Raw().QueryRow(ctx, `SELECT authority_key,version,active FROM public.sso_session_membership WHERE tenant_id=$1 AND user_id=$2 AND organization_id=$3`, string(spec.TenantID), string(spec.UserID), vector.ActiveOrganizationID).Scan(&key, &version, &active)
	if err != nil || !active || version == 0 {
		return OrganizationSessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	return OrganizationSessionAuthorityObservation{OrganizationID: vector.ActiveOrganizationID, Authority: session.AuthorityBinding{ScopeKey: key, Version: version}, ReadStartedAt: start, ValidUntil: start.Add(20 * time.Second)}, nil
}

func (*ssoOIDCSessionOrganizationFixture) RequireOrganizationSession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	binding, _, _, err := w.FeatureScope(owner)
	spec, specErr := record.Bindings()
	if err != nil || specErr != nil || binding.TenantID != spec.TenantID {
		return identity.ForbiddenError{}
	}
	vector, _ := spec.Authority.Bindings()
	rows, err := w.Query(ctx, `SELECT authority_key,version,active FROM public.sso_session_membership WHERE tenant_id=$1 AND user_id=$2 AND organization_id=$3 FOR UPDATE`, string(spec.TenantID), string(spec.UserID), vector.ActiveOrganizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var key string
	var version uint64
	var active bool
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	if err := rows.Scan(&key, &version, &active); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil || !active || !vector.Organization.Present || key != vector.Organization.Binding.ScopeKey || version != vector.Organization.Binding.Version {
		return identity.ForbiddenError{}
	}
	return nil
}

// The protocol-owner seam supplies fixed preparation output, not provider
// verification. The kernel, capability participant and all non-organization
// authority/persistence paths below use their real implementations.
type ssoOIDCSessionInvocation struct {
	effect                       *SSOOIDCSigninEffect
	original                     identity.Command
	declaration                  kernel.CommandPlan
	flow                         session.PreAuthTransaction
	mode                         string
	effectEntered                bool
	applied, finalEntered, final bool
	retained                     kernel.Work
	consumption                  kernel.CapabilityReservationBinding
}

func (*ssoOIDCSessionInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
}
func (*ssoOIDCSessionInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{ssoOIDCSessionOperation()}
}
func (p *ssoOIDCSessionInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.original || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != ssoOIDCSessionOperation() || plan.Capability == nil || p.declaration.Capability == nil || *plan.Capability != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	_, err := SSOOIDCSigninSession(command)
	return err
}
func (p *ssoOIDCSessionInvocation) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}
func (p *ssoOIDCSessionInvocation) ValidateSSOOIDCSigninConsumption(command identity.Command, proof kernel.CapabilityPlan) error {
	if command != p.original || p.declaration.Capability == nil || proof != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *ssoOIDCSessionInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	spec, ok := command.Feature()
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || !ok || command != p.original || binding != spec.Binding || feature.Operation != ssoOIDCSessionOperation() {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (p *ssoOIDCSessionInvocation) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return (ssoOIDCSessionPreparation{}).Generate(ctx, generation)
}
func (p *ssoOIDCSessionInvocation) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if command != p.original || generation == 0 || len(wire) != 8 || binary.BigEndian.Uint64(wire) != generation {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	return command, p.declaration, ctx.Err()
}
func (p *ssoOIDCSessionInvocation) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return ssoOIDCSessionPreparation{}, ctx.Err()
}
func (p *ssoOIDCSessionInvocation) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	return ssoOIDCSessionPreparation{}, nil
}

type ssoOIDCSessionPreparation struct{}

func (ssoOIDCSessionPreparation) Check(ctx context.Context) error { return ctx.Err() }
func (ssoOIDCSessionPreparation) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	return binary.BigEndian.AppendUint64(nil, generation), ctx.Err()
}

func (p *ssoOIDCSessionInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained = w
	consumed, err := w.SSOOIDCSigninConsumption(p)
	spec, ok := command.Feature()
	if err != nil || !ok || command != p.original || consumed.Command != spec.Binding || consumed.Plan != *p.declaration.Capability || consumed.Generation == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.consumption = consumed
	if p.mode == "reconstructed-command" {
		cookie, _ := command.PreAuthCookie()
		command, err = identity.NewFeaturePreAuthCommand(spec, cookie)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.effectEntered = true
	receipt, err := p.effect.Apply(ctx, w, p, command, p.flow)
	p.applied = err == nil
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.mode == "rollback" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if p.mode == "late-membership-removed" {
		if _, err := w.Exec(ctx, `UPDATE public.sso_session_membership SET active=false WHERE tenant_id='guest-tenant' AND user_id='enterprise-user' AND organization_id='selected-org'`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return receipt, nil
}
func (p *ssoOIDCSessionInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalEntered = true
	if err := p.effect.CheckCurrent(ctx, w, p, command); err != nil {
		return err
	}
	p.final = true
	return nil
}
func (p *ssoOIDCSessionInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func TestSSOOIDCSigninSessionPreparedPostgres(t *testing.T) {
	ctx, pool, repository := anonymousSessionDatabase(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 30}
	prepared := kernel.CounterPreparationMigrationSource{Base: kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 31}, Version: 32}, Version: 33}
	history, err := prepared.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() < 30 {
			continue
		}
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("native account and retained preparation history", err)
		}
	}
	for _, source := range []migrations.Source{mfapg.MigrationSource{Version: 34}, PreAuthMigrationSource{Schema: "session_store", Version: 35}, SSOOIDCSigninMigrationSource{Schema: "session_store", Version: 36, ValidationVersion: 37, PreviousConstraint: "session_issuances_purpose_anonymous_v1"}, CSRFMigrationSource{Schema: "session_store", Version: 38}} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("native session and factor history", err)
			}
		}
	}
	capabilityHistory := capabilitypg.Migrations()
	entries, err := fs.ReadDir(capabilityHistory, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(capabilityHistory, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal("real capability history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('guest-tenant','enterprise-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'guest-tenant','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'guest-tenant','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('guest-tenant','enterprise-user',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('guest-tenant','enterprise-user','enterprise-credential',3,'sso',1,true);
WITH a AS (SELECT 'oidc'::text AS provider,'https://issuer.example'::text AS issuer,'enterprise-subject'::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT 'guest-tenant','enterprise-user','enterprise-account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a;
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('guest-tenant','enterprise-user','enterprise-credential','enterprise-account');
CREATE TABLE public.sso_session_membership(tenant_id text NOT NULL,user_id text NOT NULL,organization_id text NOT NULL,authority_key text NOT NULL,version bigint NOT NULL CHECK(version>0),active boolean NOT NULL,PRIMARY KEY(tenant_id,user_id,organization_id));
INSERT INTO public.sso_session_membership VALUES('guest-tenant','enterprise-user','selected-org','organization:guest-tenant:selected-org',7,true)`); err != nil {
		t.Fatal("actual account/factor and explicit organization fixture rows", err)
	}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "sso-oidc", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	policyScope := policy.AuthorityScope{TenantID: "guest-tenant", PolicyNamespace: profile.PolicyNamespace, SubjectID: "enterprise-user"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policyScope, time.Second); err != nil {
		t.Fatal(err)
	}
	organization := &ssoOIDCSessionOrganizationFixture{pool: pool}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	effect, err := NewSSOOIDCSigninEffect(config, profile, organization)
	if err != nil {
		t.Fatal(err)
	}
	native, err := NewRepository(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "existing-family", "reconstructed-command", "stale-organization", "late-membership-removed", "rollback", "audit-failure", "audit-fails-success-only", "outbox-failure"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE public.sso_session_membership SET version=7,active=true`); err != nil {
				t.Fatal(err)
			}
			command, record, flow, capability := ssoOIDCSessionPreparedFixture(t, ctx, pool, repository, organization, profile, mode)
			feature, _ := command.Feature()
			binding := feature.Binding
			spec, _ := record.Bindings()
			var existingFamily string
			if mode == "existing-family" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(spec.TenantID), spec.FamilyID, string(spec.UserID), spec.IssuedAt.Add(-time.Minute).Format(storedTimeLayout)); err != nil {
					t.Fatal("preexisting exact same-user active family", err)
				}
				if err := pool.Raw().QueryRow(ctx, `SELECT to_jsonb(f)::text FROM session_store.families f WHERE tenant_id=$1 AND family_id=$2`, string(spec.TenantID), spec.FamilyID).Scan(&existingFamily); err != nil {
					t.Fatal(err)
				}
			}
			owner := &ssoOIDCSessionInvocation{effect: effect, original: command, flow: flow, mode: mode}
			var auditing kernel.Contributor = &revokeAudit{fail: mode == "audit-failure"}
			if mode == "audit-fails-success-only" {
				auditing = &ssoOIDCSessionSuccessAuditFailure{}
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, auditing, &revokeOutbox{fail: mode == "outbox-failure"}, owner, capabilitypg.NewParticipant()})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: spec.IssuedAt, Action: "identity.sso.login", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "sso_login_transaction", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "sso_login_transaction", "aggregate.id": binding.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(binding, feature.Operation, "sso_login_transaction", seed)
			if err != nil {
				t.Fatal(err)
			}
			transition := kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}
			owner.declaration = kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "sso_login_transaction", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: feature.Operation}, Capability: &capability, Lifecycle: &transition, Audits: []kernel.AuditPlan{{EventType: "identity.sso.login", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareFeaturePreparationPlan(command, owner.declaration)
			if err != nil {
				t.Fatal("prepare original enterprise callback", err)
			}
			if mode == "stale-organization" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE public.sso_session_membership SET version=8`); err != nil {
					t.Fatal(err)
				}
			}
			result, executionErr := coordinator.ExecutePreparedFeature(ctx, command, plan)
			success := mode == "commit"
			if owner.retained == (kernel.Work{}) {
				t.Fatal("callback did not reach Apply after actual capability consumption", executionErr)
			}
			if success && (executionErr != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final || result.Feature == nil || result.Feature.BeforeVersion != 1 || result.Feature.AfterVersion != 2) {
				t.Fatal("original enterprise session failed", result.Outcome, owner.applied, owner.final, executionErr)
			}
			if mode == "audit-failure" {
				var unknown identity.UnknownCommitError
				if result.Outcome != identity.CommitOutcomeUnknown || !errors.As(executionErr, &unknown) || unknown.CommandID != binding.CommandID {
					t.Fatal("unavailable terminal-failure audit fabricated a known outcome", result.Outcome, executionErr)
				}
			} else if !success && (executionErr == nil || result.Outcome != identity.CommitOutcomeNotCommitted) {
				t.Fatal("denied enterprise session did not roll back", result.Outcome, executionErr)
			}
			if mode == "existing-family" {
				var conflict identity.ConflictError
				if !owner.effectEntered || owner.applied || owner.finalEntered || !errors.As(executionErr, &conflict) {
					t.Fatal("existing same-user family did not conflict inside session effect", executionErr)
				}
				var retainedFamily string
				if err := pool.Raw().QueryRow(ctx, `SELECT to_jsonb(f)::text FROM session_store.families f WHERE tenant_id=$1 AND family_id=$2`, string(spec.TenantID), spec.FamilyID).Scan(&retainedFamily); err != nil || retainedFamily != existingFamily {
					t.Fatal("denied reuse changed the original active family or version", err)
				}
			}
			if (mode == "reconstructed-command" || mode == "stale-organization") && (owner.applied || owner.finalEntered) {
				t.Fatal("Apply denial escaped to final commit check")
			}
			if mode == "late-membership-removed" && (!owner.applied || !owner.finalEntered || owner.final) {
				t.Fatal("late membership removal did not deny exact final admission")
			}
			if (mode == "rollback" || mode == "audit-failure" || mode == "audit-fails-success-only" || mode == "outbox-failure") && !owner.applied {
				t.Fatal("failure control never reached staged session", executionErr)
			}
			if err := effect.CheckCurrent(ctx, owner.retained, owner, command); err == nil {
				t.Fatal("returned Work retained enterprise session authority")
			}
			var sessions, families, issuances, uses int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT state,uses,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$2 AND session_id=$3),(SELECT count(*) FROM session_store.families WHERE tenant_id=$2 AND family_id=$4),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$2 AND session_id=$3) FROM public.capability_identity_one_use WHERE capability_id=$1`, capability.CapabilityID, string(spec.TenantID), spec.SessionID, spec.FamilyID).Scan(&state, &uses, &sessions, &families, &issuances); err != nil {
				t.Fatal(err)
			}
			want, wantCapability, wantFlow := 0, "released", "issued"
			if success {
				want, wantCapability, wantFlow = 1, "finalized", "consumed"
			} else if mode == "audit-failure" {
				// Abort persists the failure audit before releasing reserved
				// custody; an audit outage must leave that grant reserved.
				wantCapability = "reserved"
			}
			wantFamilies := want
			if mode == "existing-family" {
				wantFamilies = 1
			}
			if sessions != want || families != wantFamilies || issuances != want || uses != want || state != wantCapability {
				t.Fatal("session/family/issuance/capability effects were not atomic", sessions, families, issuances, uses, state)
			}
			var audits, successfulAudits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE outcome=$2),(SELECT count(*) FROM public.revoke_outbox WHERE command_id=$1) FROM public.revoke_audit WHERE command_id=$1`, string(binding.CommandID), int64(audit.OutcomeSucceeded)).Scan(&audits, &successfulAudits, &events); err != nil {
				t.Fatal(err)
			}
			wantAudits := 1
			if mode == "audit-failure" {
				wantAudits = 0
			}
			if audits != wantAudits || successfulAudits != want || events != want {
				t.Fatal("success audit or lifecycle escaped rollback, or terminal failure audit was omitted", audits, successfulAudits, events)
			}
			flowSpec, _ := flow.Bindings()
			var flowState, flowVersion, flowGeneration string
			var flowWire, flowCommand, flowFingerprint []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT state,version::text,record,command_id,fingerprint,COALESCE(generation::text,'') FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(spec.TenantID), string(flowSpec.Binding.ID)).Scan(&flowState, &flowVersion, &flowWire, &flowCommand, &flowFingerprint, &flowGeneration); err != nil {
				t.Fatal(err)
			}
			originalFlow, _ := encodePreAuth(flow)
			wantVersion := "1"
			if success {
				wantVersion = "3"
			}
			if flowState != wantFlow || flowVersion != wantVersion || !bytes.Equal(flowWire, originalFlow) {
				t.Fatal("original browser was replaced, renewed or terminalized outside commit", flowState, flowVersion)
			}
			if success {
				commandID, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.CommandID))
				if err != nil || !bytes.Equal(flowCommand, commandID) || !bytes.Equal(flowFingerprint, owner.consumption.Fingerprint[:]) || flowGeneration != strconv.FormatUint(owner.consumption.Generation, 10) {
					t.Fatal("original browser finalized for different capability custody", err)
				}
			} else if len(flowCommand) != 0 || len(flowFingerprint) != 0 || flowGeneration != "" {
				t.Fatal("rolled-back callback retained provisional browser custody")
			}
			stored, readErr := native.Get(ctx, spec.TenantID, spec.SessionID)
			if !success {
				if !errors.Is(readErr, ErrRecordAbsent) || stored != (StoredSession{}) {
					t.Fatal("denied callback disclosed a provisional session", readErr)
				}
			} else {
				wantWire, _, _ := encodeRecord(record)
				gotWire, _, encodeErr := encodeRecord(stored.Session)
				if readErr != nil || encodeErr != nil || !bytes.Equal(wantWire, gotWire) || stored.CurrentFamilyVersion != 1 || stored.Revoked || stored.FamilyRevoked {
					t.Fatal("persisted enterprise session changed original authority/Remember/CSRF or new-family version", readErr, encodeErr)
				}
				retained, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, binding, transition, ssoOIDCSigninIssuanceDigest)
				if err != nil || status != kernel.RecoveryCommitted || retained.UserID != spec.UserID || retained.SessionID != spec.SessionID || retained.FamilyID != spec.FamilyID {
					t.Fatal("retained issuance lost the selected identity", err)
				}
				if _, wrongStatus, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, binding, transition, oauthSigninIssuanceDigest); err != nil || wrongStatus != kernel.RecoveryUnknown {
					t.Fatal("enterprise retained identity accepted social issuance domain", err)
				}
				replayed, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
				if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Binding != binding || replayed.Feature == nil || *replayed.Feature != *result.Feature {
					t.Fatal("original enterprise callback replay lost its retained receipt", err)
				}
			}
			if mode == "late-membership-removed" {
				var active bool
				if err := pool.Raw().QueryRow(ctx, `SELECT active FROM public.sso_session_membership WHERE tenant_id='guest-tenant' AND user_id='enterprise-user' AND organization_id='selected-org'`).Scan(&active); err != nil || !active {
					t.Fatal("late membership mutation escaped rollback", err)
				}
			}
		})
	}
}

func ssoOIDCSessionPreparedFixture(t *testing.T, ctx context.Context, pool *database.Pool, repository *kernel.Repository, organization *ssoOIDCSessionOrganizationFixture, profile IdentifierAdmissionConfig, mode string) (identity.Command, session.Session, session.PreAuthTransaction, kernel.CapabilityPlan) {
	t.Helper()
	account, err := repository.GetSSOOIDCSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: "guest-tenant", Provider: "oidc", Issuer: "https://issuer.example", Subject: "enterprise-subject"})
	if err != nil {
		t.Fatal("real SSO-owned selected account", err)
	}
	directory, err := repository.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: account.Account.TenantID})
	if err != nil || !directory.Enabled {
		t.Fatal("actual current directory", err)
	}
	factors, err := mfapg.ReadSSOOIDCSigninFactors(ctx, pool, account.Account.TenantID, account.Account.UserID, time.Second)
	if err != nil {
		t.Fatal("actual current known-empty MFA", err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	flowID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := ssoOIDCSessionOperation()
	binding := identity.CommandBinding{CommandID: id, TenantID: account.Account.TenantID, ActorID: "enterprise-signin-service", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: string(flowID), RecordID: string(start), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "enterprise-signin", PolicyVersion: 1, CorrelationID: string(id)}
	spec, _ := testSession(t).Bindings()
	spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID = "enterprise-session-"+mode, "enterprise-family-"+mode, binding.TenantID, account.Account.UserID
	spec.Version, spec.FamilyVersion, spec.IssuedAt, spec.LastActivityAt = 1, 1, now, now
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(id), Tenant: string(spec.TenantID), Subject: string(spec.UserID), Method: "sso-oidc", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: profile.Audience, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: string(account.Credential.Credential.ID), CredentialVersion: account.Credential.Credential.Version}
	spec.Audience = profile.Audience
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{83}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.KernelAuthorityKeys(directory.Query, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sessionKeys, err := SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	policyKey, err := (policy.AuthorityScope{TenantID: authorization.TenantID(spec.TenantID), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(spec.UserID)}).Key()
	if err != nil {
		t.Fatal(err)
	}
	factorKey, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	a := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	vector := session.AuthoritySnapshotSpec{Global: a(keys.Global, directory.GlobalVersion), Tenant: a(keys.Tenant, directory.TenantVersion), User: a(keys.User, account.Credential.UserAuthorityVersion), Identifier: a(keys.Identifier, account.Credential.IdentifierAuthorityVersion), Credential: a(keys.Credential, account.Credential.CredentialAuthorityVersion), Session: a(sessionKeys.Session, 1), SessionFamily: a(sessionKeys.Family, 1), Authorization: a(policyKey, 1), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(factorKey, factors.Version())}, ActiveOrganizationID: "selected-org", Organization: session.OptionalAuthorityBinding{Present: true, Binding: a("organization:guest-tenant:selected-org", 7)}}
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := organization.ObserveOrganizationSession(ctx, record)
	if err != nil || observed.Authority != vector.Organization.Binding {
		t.Fatal("retained organization fixture observation", err)
	}
	record = withCSRFState(t, record, 1)
	flowSpec, _ := testPreAuth(t, now).Bindings()
	flowSpec.Binding.ID = flowID
	flowSpec.Binding.Intent.TenantID, flowSpec.Binding.Intent.Action = binding.TenantID, binding.OperationID
	flowSpec.Binding.Intent.PolicyID, flowSpec.Binding.Intent.PolicyVersion, flowSpec.Binding.Intent.Remember = binding.PolicyID, binding.PolicyVersion, spec.Remember
	flowSpec.Binding.Intent.Purpose = session.PreAuthSessionIssuance
	cookieToken, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	flowSpec.Cookie, err = cookieToken.PreAuthDigest(key, flowSpec.Binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(flowSpec)
	if err != nil {
		t.Fatal(err)
	}
	flowTx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = flowTx.Rollback(cleanup)
	}()
	if err := InsertPreAuth(ctx, preAuthTestTx{flowTx}, Config{Schema: "session_store", MaximumDuration: time.Second}, flow); err != nil {
		t.Fatal("original issued browser transaction", err)
	}
	if err := flowTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	cookieWire, err := cookieToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	fields, err := SSOOIDCSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	accountFields, err := kernel.SSOOIDCSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	fields = append(fields, accountFields...)
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, auth.NewBearerCredential(cookieWire))
	if err != nil {
		t.Fatal(err)
	}
	proof := kernel.CapabilityPlan{CapabilityID: string(id), Purpose: "identity.sso.oidc-callback", ReplayKeyVersion: 1, ReplayDigest: sha256.Sum256([]byte(id)), ProofFingerprint: [32]byte{83}, ExpiresAt: now.Add(2 * time.Minute).Truncate(time.Second), MaxUses: 1}
	// Fixture issuance metadata does not claim cryptographic OIDC verification.
	// The actual participant owns reservation, rollback release and finalization.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(binding.TenantID), string(proof.Purpose), proof.ReplayKeyVersion, proof.ReplayDigest[:], proof.CapabilityID, proof.ProofFingerprint[:], proof.ExpiresAt, proof.MaxUses); err != nil {
		t.Fatal(err)
	}
	return command, record, flow, proof
}
