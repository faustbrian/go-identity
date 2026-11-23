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
	"github.com/faustbrian/go-capability/v2"
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
type ssoOIDCSessionOrganizationFixture struct {
	pool         *database.Pool
	requireCalls int
	update       *ssoOIDCSessionOrganizationUpdateFixture
}

var errSSOOIDCSessionOrganizationUpdate = errors.New("organization update denied")
var errSSOSAMLTestForeignFactorAuthority = errors.New("foreign callback obtained SAML factor authority")

type ssoOIDCSessionOrganizationUpdateFixture struct {
	organization *ssoOIDCSessionOrganizationFixture
	original     identity.Command
	flow         session.PreAuthTransaction
	wantWork     kernel.Work
	wantOwner    kernel.FeatureExecutionContributor
	calls        int
	fail         bool
	expire       bool
}

func (p *ssoOIDCSessionOrganizationUpdateFixture) UpdateSSOOIDCOrganization(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	p.calls++
	if p.calls != 1 || p.organization.requireCalls != 0 || w != p.wantWork || owner != p.wantOwner || command != p.original {
		return errors.New("organization update did not precede the first fence in the original Work")
	}
	wantRecord, err := SSOOIDCSigninSession(command)
	if err != nil {
		return err
	}
	wantWire, _, err := encodeRecord(wantRecord)
	if err != nil {
		return err
	}
	gotWire, _, err := encodeRecord(record)
	if err != nil || !bytes.Equal(gotWire, wantWire) {
		return errors.New("organization update changed the original session")
	}
	if err := RequireSession(ctx, w, Config{Schema: "session_store", MaximumDuration: time.Second}, record); err != nil {
		return err
	}
	spec, _ := record.Bindings()
	flow, _ := p.flow.Bindings()
	rows, err := w.Query(ctx, `SELECT state,version FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(spec.TenantID), string(flow.Binding.ID))
	if err != nil {
		return err
	}
	var state string
	var version uint64
	if !rows.Next() {
		rows.Close()
		return errors.New("organization update ran before the original browser write")
	}
	err = rows.Scan(&state, &version)
	complete := !rows.Next() && rows.Err() == nil
	rows.Close()
	if err != nil || !complete || state != "consumed" || version != 3 {
		return errors.New("organization update ran before browser finalization")
	}
	if _, err := w.Exec(ctx, `UPDATE public.sso_session_membership SET provider_updates=provider_updates+1 WHERE tenant_id=$1 AND user_id=$2 AND organization_id='selected-org'`, string(spec.TenantID), string(spec.UserID)); err != nil {
		return err
	}
	if p.fail {
		return errSSOOIDCSessionOrganizationUpdate
	}
	if p.expire {
		timer := time.NewTimer(time.Until(spec.Authentication.Proof.ExpiresAt.Add(time.Millisecond)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

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

func (p *ssoOIDCSessionOrganizationFixture) RequireOrganizationSession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	p.requireCalls++
	if p.update != nil && p.update.calls != 1 {
		return errors.New("organization fence preceded the synchronous update")
	}
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
	effect                       ssoSessionEffectFixture
	original                     identity.Command
	declaration                  kernel.CommandPlan
	flow                         session.PreAuthTransaction
	mode                         string
	effectEntered                bool
	applied, finalEntered, final bool
	retained                     kernel.Work
	consumption                  kernel.CapabilityReservationBinding
	organizationUpdate           SSOOIDCOrganizationUpdate
	applyErr                     error
}

type ssoSessionEffectFixture interface {
	Apply(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command, session.PreAuthTransaction) (identity.FeatureReceipt, error)
	CheckCurrent(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Recover(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error)
}

func (p *ssoOIDCSessionInvocation) operation() identity.FeatureOperation {
	switch p.effect.(type) {
	case *SSOOAuth2SigninEffect:
		return kernel.SSOOAuth2SigninOperation()
	case *SSOSAMLSigninEffect:
		return kernel.SSOSAMLSigninOperation()
	default:
		return ssoOIDCSessionOperation()
	}
}

func (p *ssoOIDCSessionInvocation) Descriptor() kernel.ContributorDescriptor {
	switch p.operation() {
	case kernel.SSOOAuth2SigninOperation():
		return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oauth2-login-callback", Version: 1}
	case kernel.SSOSAMLSigninOperation():
		return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-login-callback", Version: 1}
	default:
		return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
	}
}
func (p *ssoOIDCSessionInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}
func (p *ssoOIDCSessionInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.original || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != p.operation() || plan.Capability == nil || p.declaration.Capability == nil || *plan.Capability != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	if p.operation() == kernel.SSOOAuth2SigninOperation() {
		_, err := SSOOAuth2SigninSession(command)
		return err
	}
	if p.operation() == kernel.SSOSAMLSigninOperation() {
		_, err := SSOSAMLSigninSession(command)
		return err
	}
	_, err := SSOOIDCSigninSession(command)
	return err
}
func (p *ssoOIDCSessionInvocation) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}
func (p *ssoOIDCSessionInvocation) ValidateSSOOIDCSigninConsumption(command identity.Command, proof kernel.CapabilityPlan) error {
	if p.operation() != ssoOIDCSessionOperation() || command != p.original || p.declaration.Capability == nil || proof != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *ssoOIDCSessionInvocation) ValidateSSOOAuth2SigninConsumption(command identity.Command, proof kernel.CapabilityPlan) error {
	if p.operation() != kernel.SSOOAuth2SigninOperation() || command != p.original || p.declaration.Capability == nil || proof != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *ssoOIDCSessionInvocation) ValidateSSOSAMLSigninConsumption(command identity.Command, proof kernel.CapabilityPlan) error {
	if p.operation() != kernel.SSOSAMLSigninOperation() || command != p.original || p.declaration.Capability == nil || proof != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *ssoOIDCSessionInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	spec, ok := command.Feature()
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || !ok || command != p.original || binding != spec.Binding || feature.Operation != p.operation() {
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
	var consumed kernel.CapabilityReservationBinding
	var err error
	switch p.operation() {
	case kernel.SSOOAuth2SigninOperation():
		consumed, err = w.SSOOAuth2SigninConsumption(p)
	case kernel.SSOSAMLSigninOperation():
		consumed, err = w.SSOSAMLSigninConsumption(p)
	default:
		consumed, err = w.SSOOIDCSigninConsumption(p)
	}
	spec, ok := command.Feature()
	if err != nil || !ok || command != p.original || consumed.Command != spec.Binding || consumed.Plan != *p.declaration.Capability || consumed.Generation == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.consumption = consumed
	if p.mode == "foreign-saml-factor-guard" {
		state, err := mfapg.RequireSSOSAMLSigninFactors(ctx, w, p, command, 1)
		if err == nil || state.Version() != 0 {
			err = errSSOSAMLTestForeignFactorAuthority
		}
		p.applyErr = err
		return identity.FeatureReceipt{}, err
	}
	if p.mode == "reconstructed-command" {
		cookie, _ := command.PreAuthCookie()
		command, err = identity.NewFeaturePreAuthCommand(spec, cookie)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.effectEntered = true
	var receipt identity.FeatureReceipt
	if strings.HasPrefix(p.mode, "organization-update") {
		if update, ok := p.organizationUpdate.(*ssoOIDCSessionOrganizationUpdateFixture); ok && update != nil {
			update.wantWork, update.wantOwner = w, p
		}
		receipt, err = p.effect.(*SSOOIDCSigninEffect).ApplyWithOrganizationUpdate(ctx, w, p, command, p.flow, p.organizationUpdate)
	} else {
		receipt, err = p.effect.Apply(ctx, w, p, command, p.flow)
	}
	p.applyErr = err
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
	if p.mode == "late-factor-enrolled" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id='guest-tenant' AND user_id='enterprise-user'`); err != nil {
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
	testSSOSigninSessionPreparedPostgres(t, "sso-oidc")
}

func TestSSOOAuth2SigninSessionPreparedPostgres(t *testing.T) {
	testSSOSigninSessionPreparedPostgres(t, "sso-oauth2")
}

func TestSSOSAMLSigninSessionPreparedPostgres(t *testing.T) {
	testSSOSigninSessionPreparedPostgres(t, "sso-saml")
}

const samlFixtureProvider = "sso.saml.v1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const samlFixtureIssuer = "urn:example:original-saml-idp"

func testSSOSigninSessionPreparedPostgres(t *testing.T, method string) {
	t.Helper()
	ctx, pool, repository := anonymousSessionDatabase(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 30}
	prepared := kernel.CounterPreparationMigrationSource{Base: kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 31}, Version: 32}, Version: 33}
	start := kernel.SSOOIDCPreparationErasureMigrationSource{Base: prepared, Version: 39}
	oidc := kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: start, Version: 40}
	oauth := kernel.SSOOAuth2CallbackPreparationErasureMigrationSource{Base: oidc, Version: 41}
	var kernelHistory migrations.Source = oauth
	if method == "sso-saml" {
		refresh := kernel.SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: oauth, Version: 44}
		kernelHistory = kernel.SSOSAMLCallbackPreparationErasureMigrationSource{Base: refresh, Version: 45}
	}
	history, err := kernelHistory.Load(ctx)
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
	sessionHistory := []migrations.Source{mfapg.MigrationSource{Version: 34}, PreAuthMigrationSource{Schema: "session_store", Version: 35}, SSOOIDCSigninMigrationSource{Schema: "session_store", Version: 36, ValidationVersion: 37, PreviousConstraint: "session_issuances_purpose_anonymous_v1"}, CSRFMigrationSource{Schema: "session_store", Version: 38}, SSOOAuth2SigninMigrationSource{Schema: "session_store", Version: 42, ValidationVersion: 43}}
	if method == "sso-saml" {
		sessionHistory = append(sessionHistory, SSOSAMLSigninMigrationSource{Schema: "session_store", Version: 46, ValidationVersion: 47})
	}
	for _, source := range sessionHistory {
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
CREATE TABLE public.sso_session_membership(tenant_id text NOT NULL,user_id text NOT NULL,organization_id text NOT NULL,authority_key text NOT NULL,version bigint NOT NULL CHECK(version>0),active boolean NOT NULL,provider_updates integer NOT NULL DEFAULT 0,PRIMARY KEY(tenant_id,user_id,organization_id));
INSERT INTO public.sso_session_membership(tenant_id,user_id,organization_id,authority_key,version,active) VALUES('guest-tenant','enterprise-user','selected-org','organization:guest-tenant:selected-org',7,true)`); err != nil {
		t.Fatal("actual account/factor and explicit organization fixture rows", err)
	}
	if method == "sso-saml" {
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.accounts SET provider=$1::text,issuer=$2::text,
subject_key=sha256(convert_to(octet_length($1::text)::text||':'||$1::text||octet_length($2::text)::text||':'||$2::text||octet_length(subject)::text||':'||subject,'UTF8'))
WHERE tenant_id='guest-tenant' AND account_id='enterprise-account'`, samlFixtureProvider, samlFixtureIssuer); err != nil {
			t.Fatal("install exact distinct SAML issuer fixture", err)
		}
	}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: method, CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	policyScope := policy.AuthorityScope{TenantID: "guest-tenant", PolicyNamespace: profile.PolicyNamespace, SubjectID: "enterprise-user"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policyScope, time.Second); err != nil {
		t.Fatal(err)
	}
	organization := &ssoOIDCSessionOrganizationFixture{pool: pool}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	var effect ssoSessionEffectFixture
	switch method {
	case "sso-oauth2":
		effect, err = NewSSOOAuth2SigninEffect(config, profile, organization)
	case "sso-saml":
		effect, err = NewSSOSAMLSigninEffect(config, profile, organization)
	default:
		effect, err = NewSSOOIDCSigninEffect(config, profile, organization)
	}
	if err != nil {
		t.Fatal(err)
	}
	native, err := NewRepository(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	modes := []string{"commit", "organization-update", "organization-update-failure", "organization-update-expired", "organization-update-nil", "organization-update-typed-nil", "existing-family", "reconstructed-command", "stale-organization", "late-membership-removed", "rollback", "audit-failure", "audit-fails-success-only", "outbox-failure"}
	if method == "sso-saml" {
		modes = []string{"commit", "existing-family", "reconstructed-command", "late-membership-removed", "late-factor-enrolled", "rollback", "outbox-failure"}
	} else {
		modes = append(modes, "foreign-saml-factor-guard")
	}
	for _, mode := range modes {
		if method != "sso-oidc" && strings.HasPrefix(mode, "organization-update") {
			continue // This separate organization effect belongs only to OIDC.
		}
		t.Run(mode, func(t *testing.T) {
			organization.requireCalls, organization.update = 0, nil
			if _, err := pool.Raw().Exec(ctx, `UPDATE public.sso_session_membership SET version=7,active=true,provider_updates=0`); err != nil {
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
			if mode == "organization-update" || mode == "organization-update-failure" || mode == "organization-update-expired" {
				organization.update = &ssoOIDCSessionOrganizationUpdateFixture{organization: organization, original: command, flow: flow, fail: mode == "organization-update-failure", expire: mode == "organization-update-expired"}
				owner.organizationUpdate = organization.update
			} else if mode == "organization-update-typed-nil" {
				owner.organizationUpdate = (*ssoOIDCSessionOrganizationUpdateFixture)(nil)
			}
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
			success := mode == "commit" || mode == "organization-update"
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
			if organization.update != nil && organization.update.calls != 1 {
				t.Fatal("organization update did not execute exactly once", organization.update.calls, executionErr)
			}
			if mode == "organization-update-failure" && (!errors.Is(owner.applyErr, errSSOOIDCSessionOrganizationUpdate) || owner.applied || owner.finalEntered || organization.requireCalls != 0) {
				t.Fatal("update error was not propagated before the first organization fence", owner.applyErr)
			}
			if mode == "organization-update-expired" {
				var forbidden identity.ForbiddenError
				if !errors.As(owner.applyErr, &forbidden) || owner.applied || owner.finalEntered || organization.requireCalls != 1 {
					t.Fatal("original proof expiry was not checked after organization update", owner.applyErr)
				}
			}
			if mode == "organization-update-nil" || mode == "organization-update-typed-nil" {
				if !errors.Is(owner.applyErr, session.ErrInvalidSessionCommand) || owner.applied || owner.finalEntered || organization.requireCalls != 0 {
					t.Fatal("absent update did not fail closed", owner.applyErr)
				}
			}
			var providerUpdates int
			if err := pool.Raw().QueryRow(ctx, `SELECT provider_updates FROM public.sso_session_membership WHERE tenant_id='guest-tenant' AND user_id='enterprise-user' AND organization_id='selected-org'`).Scan(&providerUpdates); err != nil {
				t.Fatal(err)
			}
			wantProviderUpdates := 0
			if mode == "organization-update" {
				wantProviderUpdates = 1
			}
			if providerUpdates != wantProviderUpdates {
				t.Fatal("organization update did not commit or roll back with the session", providerUpdates)
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
			if mode == "foreign-saml-factor-guard" && (owner.consumption.Generation == 0 || owner.applyErr == nil || errors.Is(owner.applyErr, errSSOSAMLTestForeignFactorAuthority) || owner.finalEntered) {
				t.Fatal("SAML factor guard did not deny the live sibling callback before final admission", owner.applyErr)
			}
			if (mode == "late-membership-removed" || mode == "late-factor-enrolled") && (!owner.applied || !owner.finalEntered || owner.final) {
				t.Fatal("late authority change did not deny exact final admission")
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
				issuanceDigest, otherDigest := ssoOIDCSigninIssuanceDigest, ssoOAuth2SigninIssuanceDigest
				if method == "sso-oauth2" {
					issuanceDigest, otherDigest = otherDigest, issuanceDigest
				}
				if method == "sso-saml" {
					issuanceDigest = ssoSAMLSigninIssuanceDigest
				}
				retained, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, binding, transition, issuanceDigest)
				if err != nil || status != kernel.RecoveryCommitted || retained.UserID != spec.UserID || retained.SessionID != spec.SessionID || retained.FamilyID != spec.FamilyID {
					t.Fatal("retained issuance lost the selected identity", err)
				}
				if _, wrongStatus, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, binding, transition, oauthSigninIssuanceDigest); err != nil || wrongStatus != kernel.RecoveryUnknown {
					t.Fatal("enterprise retained identity accepted social issuance domain", err)
				}
				if _, wrongStatus, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, binding, transition, otherDigest); err != nil || wrongStatus != kernel.RecoveryUnknown {
					t.Fatal("enterprise retained identity accepted the other SSO protocol's issuance domain", err)
				}
				replayed, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
				if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Binding != binding || replayed.Feature == nil || *replayed.Feature != *result.Feature {
					t.Fatal("original enterprise callback replay lost its retained receipt", err)
				}
				var replaySessions, replayFamilies, replayIssuances, replayUses int
				if err := pool.Raw().QueryRow(ctx, `SELECT uses,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$2 AND session_id=$3),(SELECT count(*) FROM session_store.families WHERE tenant_id=$2 AND family_id=$4),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$2 AND session_id=$3) FROM public.capability_identity_one_use WHERE capability_id=$1`, capability.CapabilityID, string(spec.TenantID), spec.SessionID, spec.FamilyID).Scan(&replayUses, &replaySessions, &replayFamilies, &replayIssuances); err != nil || replayUses != 1 || replaySessions != 1 || replayFamilies != 1 || replayIssuances != 1 {
					t.Fatal("callback replay repeated capability consumption or session issuance", replayUses, replaySessions, replayFamilies, replayIssuances, err)
				}
				var ciphertext, ciphertextGeneration bool
				if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NOT NULL,preparation_ciphertext_generation IS NOT NULL FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, binding.CommandID)).Scan(&ciphertext, &ciphertextGeneration); err != nil || ciphertext || ciphertextGeneration {
					t.Fatal("committed callback retained temporary preparation custody", err)
				}
			}
			if mode == "late-membership-removed" {
				var active bool
				if err := pool.Raw().QueryRow(ctx, `SELECT active FROM public.sso_session_membership WHERE tenant_id='guest-tenant' AND user_id='enterprise-user' AND organization_id='selected-org'`).Scan(&active); err != nil || !active {
					t.Fatal("late membership mutation escaped rollback", err)
				}
			}
			if mode == "late-factor-enrolled" {
				var version string
				var count int
				if err := pool.Raw().QueryRow(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id='guest-tenant' AND user_id='enterprise-user'`).Scan(&version, &count); err != nil || version != "1" || count != 0 {
					t.Fatal("late factor change or session escaped original rollback", err)
				}
			}
		})
	}
}

func ssoOIDCSessionPreparedFixture(t *testing.T, ctx context.Context, pool *database.Pool, repository *kernel.Repository, organization *ssoOIDCSessionOrganizationFixture, profile IdentifierAdmissionConfig, mode string) (identity.Command, session.Session, session.PreAuthTransaction, kernel.CapabilityPlan) {
	t.Helper()
	query := kernel.ProviderSigninAccountQuery{TenantID: "guest-tenant", Provider: "oidc", Issuer: "https://issuer.example", Subject: "enterprise-subject"}
	getAccount := repository.GetSSOOIDCSigninAccount
	if profile.AuthenticationMethod == "sso-saml" {
		query.Provider, query.Issuer = samlFixtureProvider, samlFixtureIssuer
		getAccount = repository.GetSSOSAMLSigninAccount
	}
	account, err := getAccount(ctx, query)
	if err != nil {
		t.Fatal("real SSO-owned selected account", err)
	}
	directory, err := repository.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: account.Account.TenantID})
	if err != nil || !directory.Enabled {
		t.Fatal("actual current directory", err)
	}
	readFactors := mfapg.ReadSSOOIDCSigninFactors
	if profile.AuthenticationMethod == "sso-oauth2" {
		readFactors = mfapg.ReadSSOOAuth2SigninFactors
	}
	if profile.AuthenticationMethod == "sso-saml" {
		readFactors = mfapg.ReadSSOSAMLSigninFactors
	}
	factors, err := readFactors(ctx, pool, account.Account.TenantID, account.Account.UserID, time.Second)
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
	if profile.AuthenticationMethod == "sso-oauth2" {
		op = kernel.SSOOAuth2SigninOperation()
	}
	if profile.AuthenticationMethod == "sso-saml" {
		op = kernel.SSOSAMLSigninOperation()
	}
	binding := identity.CommandBinding{CommandID: id, TenantID: account.Account.TenantID, ActorID: "enterprise-signin-service", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: string(flowID), RecordID: string(start), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "enterprise-signin", PolicyVersion: 1, CorrelationID: string(id)}
	spec, _ := testSession(t).Bindings()
	spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID = "enterprise-session-"+mode, "enterprise-family-"+mode, binding.TenantID, account.Account.UserID
	spec.Version, spec.FamilyVersion, spec.IssuedAt, spec.LastActivityAt = 1, 1, now, now
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(id), Tenant: string(spec.TenantID), Subject: string(spec.UserID), Method: profile.AuthenticationMethod, Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: profile.Audience, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: string(account.Credential.Credential.ID), CredentialVersion: account.Credential.Credential.Version}
	if mode == "organization-update-expired" {
		spec.Authentication.Proof.ExpiresAt = now.Add(500 * time.Millisecond)
	}
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
	if profile.AuthenticationMethod == "sso-saml" {
		flowSpec.Binding.Intent.Origin = "https://identity.example"
		flowSpec.Binding.Intent.CallbackURL = "https://identity.example/saml2/enterprise-provider/acs"
		flowSpec.Binding.ExpiresAt = flowSpec.Binding.IssuedAt.Add(5 * time.Minute)
	}
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
	sessionFields := SSOOIDCSigninSessionFields
	selectedAccountFields := kernel.SSOOIDCSigninAccountFields
	if profile.AuthenticationMethod == "sso-oauth2" {
		sessionFields = SSOOAuth2SigninSessionFields
		selectedAccountFields = kernel.SSOOAuth2SigninAccountFields
	}
	if profile.AuthenticationMethod == "sso-saml" {
		sessionFields = SSOSAMLSigninSessionFields
		selectedAccountFields = kernel.SSOSAMLSigninAccountFields
	}
	fields, err := sessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	accountFields, err := selectedAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	fields = append(fields, accountFields...)
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, auth.NewBearerCredential(cookieWire))
	if err != nil {
		t.Fatal(err)
	}
	proof := kernel.CapabilityPlan{CapabilityID: string(id), Purpose: capability.Purpose(op.OperationID), ReplayKeyVersion: 1, ReplayDigest: sha256.Sum256([]byte(id)), ProofFingerprint: [32]byte{83}, ExpiresAt: now.Add(2 * time.Minute).Truncate(time.Second), MaxUses: 1}
	// Fixture issuance metadata does not claim cryptographic provider verification.
	// The actual participant owns reservation, rollback release and finalization.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(binding.TenantID), string(proof.Purpose), proof.ReplayKeyVersion, proof.ReplayDigest[:], proof.CapabilityID, proof.ProofFingerprint[:], proof.ExpiresAt, proof.MaxUses); err != nil {
		t.Fatal(err)
	}
	return command, record, flow, proof
}
