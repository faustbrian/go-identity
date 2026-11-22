//go:build integration

package reference_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const referenceEnterpriseJITMailbox = "first-login@enterprise.example"
const referenceEnterpriseJITSubject = "reference-enterprise-jit-subject"

// Focused filter: ^TestReferencePostgresEnterpriseOIDCJITJourney$
// The existing linked-member graph is populated and used before JIT selection;
// only the configured external signed HTTPS provider is controlled.
func TestReferencePostgresEnterpriseOIDCJITJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, enterpriseOIDC: true, enterpriseOIDCJIT: true,
	})
}

func prepareReferenceEnterpriseJITMapping(c *reference.StoreConfiguration, provider *referenceEnterpriseIssuer) {
	provider.jitMapping = true
	c.EnterpriseOIDC.Completion.Profiles[0].ClaimNames = []string{"work_mail", "verified_work_mail", "email", "email_verified"}
}

func configureReferenceEnterpriseJIT(t *testing.T, c *reference.StoreConfiguration, provider *referenceEnterpriseIssuer) {
	t.Helper()
	domain := c.PasswordSignup.Native.RegistrationDomain
	c.EnterpriseOIDC.JIT = &reference.EnterpriseOIDCJITConfiguration{Address: c.PasswordSignup.Native.Address, PolicyVersion: 1,
		Directory: kernel.SSOOIDCJITDomainConfig{ComparisonProfile: domain.ComparisonProfile,
			CurrentIdentifierKeyVersion: domain.CurrentIdentifierKeyVersion, RetainedIdentifierKeys: domain.RetainedIdentifierKeys}}
	provider.mux.Lock()
	provider.assertedClaims = map[string]any{"sub": referenceEnterpriseJITSubject, "work_mail": referenceEnterpriseJITMailbox,
		"verified_work_mail": true, "email": "unselected@other.example", "email_verified": true}
	provider.mux.Unlock()
}

type referenceEnterpriseJITLegacyState struct {
	user, authority, identifier, credential, member, memberAuthority string
	role, factor, purpose, initializedCommand, account, link         string
	activeFactors                                                    int
}

func readReferenceEnterpriseJITLegacyState(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, selected enterpriseProvisioned) referenceEnterpriseJITLegacyState {
	t.Helper()
	var state referenceEnterpriseJITLegacyState
	err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT u.version::text,u.authority_version::text,u.identifier_version::text,u.credential_version::text,
m.version::text,m.authorization_version::text,m.role,f.version::text,f.initialized_purpose,encode(f.initialized_command_id,'hex'),
a.version::text,a.social_link_version::text,f.active_factors
FROM identity.users u
JOIN organization.memberships m USING(tenant_id,user_id)
JOIN identity_mfa.factor_authorities f USING(tenant_id,user_id)
JOIN identity.accounts a USING(tenant_id,user_id)
WHERE u.tenant_id=$1::text AND u.user_id=$2::text AND m.organization_id=$3::text AND a.account_id='enterprise-fixture-link'`,
		otpTenant, string(selected.user), string(selected.organization)).
		Scan(&state.user, &state.authority, &state.identifier, &state.credential, &state.member, &state.memberAuthority,
			&state.role, &state.factor, &state.purpose, &state.initializedCommand, &state.account, &state.link, &state.activeFactors)
	if err != nil {
		t.Fatal("read the populated ordinary enterprise authority across JIT migration", err)
	}
	return state
}

func proveReferenceEnterpriseOIDCJITJourney(t *testing.T, ctx context.Context, client *http.Client, origin string, features reference.FeatureSet,
	provider *referenceEnterpriseIssuer, existing enterpriseProvisioned, deps reference.ReferenceDependencies, c reference.StoreConfiguration) {
	t.Helper()
	before := readReferenceEnterpriseJITCounts(t, ctx, deps, existing)
	prospective := existing
	prospective.user = ""
	var created identity.UserID
	proveReferenceEnterpriseOIDCCookieJourney(t, ctx, client, origin, features, provider, prospective, func(user identity.UserID) {
		created = user
		if user == "" || user == existing.user {
			t.Fatal("first-login cookie reused the preexisting administrator instead of a new enterprise identity")
		}
		assertReferenceEnterpriseJITGraph(t, ctx, deps, c, existing, user)
	})
	if created == "" {
		t.Fatal("reference first login never authenticated a newly created user")
	}
	after := readReferenceEnterpriseJITCounts(t, ctx, deps, existing)
	if after.users != before.users+1 || after.identifiers != before.identifiers+1 || after.accounts != before.accounts+1 ||
		after.credentials != before.credentials+1 || after.associations != before.associations+1 || after.memberships != before.memberships+1 ||
		after.factors != before.factors+1 || after.authorities != before.authorities+2 || after.sessions != before.sessions+1 ||
		after.families != before.families+1 || after.issuances != before.issuances+1 || after.tokens != before.tokens+1 ||
		after.version != before.version+1 || after.members != before.members+1 || after.owners != before.owners || after.credential != before.credential {
		t.Fatalf("reference JIT did not create one ordinary-member graph across session read, logout and replay: before=%+v after=%+v", before, after)
	}
}

type referenceEnterpriseJITCounts struct {
	users, identifiers, accounts, credentials, associations       int
	memberships, factors, authorities, sessions, families, tokens int
	issuances, members, owners                                    int
	version, credential                                           uint64
}

func readReferenceEnterpriseJITCounts(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, selected enterpriseProvisioned) referenceEnterpriseJITCounts {
	t.Helper()
	var counts referenceEnterpriseJITCounts
	var version, credential string
	err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM identity.users WHERE tenant_id=$1::text),
(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1::text),
(SELECT count(*) FROM identity.accounts WHERE tenant_id=$1::text),
(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1::text),
(SELECT count(*) FROM identity.account_credentials WHERE tenant_id=$1::text),
(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1::text),
(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1::text),
(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1::text),
(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1::text),
(SELECT count(*) FROM session_store.families WHERE tenant_id=$1::text),
(SELECT count(*) FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1::text),
(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1::text),member_count,owner_count,version::text,credential_version::text
FROM organization.organizations WHERE tenant_id=$1::text AND organization_id=$2::text`, otpTenant, string(selected.organization)).
		Scan(&counts.users, &counts.identifiers, &counts.accounts, &counts.credentials, &counts.associations, &counts.memberships,
			&counts.factors, &counts.authorities, &counts.sessions, &counts.families, &counts.tokens, &counts.issuances,
			&counts.members, &counts.owners, &version, &credential)
	if err != nil {
		t.Fatal("read reference JIT graph conservation", err)
	}
	counts.version, err = strconv.ParseUint(version, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	counts.credential, err = strconv.ParseUint(credential, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return counts
}

func assertReferenceEnterpriseJITGraph(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, c reference.StoreConfiguration, selected enterpriseProvisioned, user identity.UserID) {
	t.Helper()
	parsed, err := c.EnterpriseOIDC.JIT.Address.Parse(email.AddressInput(referenceEnterpriseJITMailbox))
	if err != nil {
		t.Fatal(err)
	}
	canonical := parsed.Canonical().Record()
	namespace, err := organizationpg.OrganizationAuthorityScope(otpTenant, selected.organization, user)
	if err != nil {
		t.Fatal(err)
	}
	providerNamespace, err := ssopg.SSOOIDCAccountProviderNamespace(selected.organization, selected.provider)
	if err != nil {
		t.Fatal(err)
	}
	var exactUser, exactMailbox, exactAccount, exactMember, exactFactor, exactAuthorities, exactVault bool
	err = deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT
EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1::text AND user_id=$2::text AND status='active' AND version=1 AND authority_version=1 AND identifier_version=1 AND credential_version=1),
EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1::text AND user_id=$2::text AND kind='email' AND canonical_value=$3::text AND display_value=$4::text
 AND verified AND NOT is_primary AND verification_state=2 AND version=1 AND verification_version=1 AND verified_at IS NOT NULL AND normalization_profile=$5::text AND normalization_version=$6::numeric),
EXISTS(SELECT 1 FROM identity.accounts a JOIN identity.account_credentials c USING(tenant_id,user_id,account_id)
 JOIN identity.credential_references r USING(tenant_id,user_id,credential_id)
 WHERE a.tenant_id=$1::text AND a.user_id=$2::text AND a.subject=$7::text AND a.provider=$11::text AND a.issuer=$12::text AND a.linked AND a.version=1 AND a.social_link_version=1
 AND r.kind=3 AND r.owner='sso' AND r.enabled AND r.version=1),
EXISTS(SELECT 1 FROM organization.memberships WHERE tenant_id=$1::text AND user_id=$2::text AND organization_id=$8::text AND role='member' AND state='active' AND version=1 AND authorization_version=1),
EXISTS(SELECT 1 FROM identity_mfa.factor_authorities f JOIN identity.commands j ON j.tenant_id=f.tenant_id AND j.command_id=f.initialized_command_id
 WHERE f.tenant_id=$1::text AND f.user_id=$2::text AND f.version=1 AND f.active_factors=0 AND f.initialized_purpose IS NULL
 AND f.sso_oidc_initialized_purpose='identity.sso.oidc-callback' AND j.purpose='identity.sso.oidc-callback' AND j.state='committed'),
(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1::text AND subject_id=$2::text AND policy_namespace IN ($9::text,$10::text) AND version=1)=2,
EXISTS(SELECT 1 FROM sso_providers.provider_login_token_sets v JOIN identity.accounts a USING(tenant_id,user_id,account_id)
 WHERE v.tenant_id=$1::text AND v.user_id=$2::text AND a.subject=$7::text AND octet_length(v.token_ciphertext)>0)`,
		otpTenant, string(user), canonical.Value, parsed.Display(), string(canonical.ProfileID), canonical.ProfileVersion,
		referenceEnterpriseJITSubject, string(selected.organization), c.EnterpriseOIDC.Completion.PolicyNamespace, namespace.PolicyNamespace,
		providerNamespace, c.EnterpriseOIDC.Completion.Profiles[0].Metadata.Issuer).
		Scan(&exactUser, &exactMailbox, &exactAccount, &exactMember, &exactFactor, &exactAuthorities, &exactVault)
	if err != nil || !exactUser || !exactMailbox || !exactAccount || !exactMember || !exactFactor || !exactAuthorities || !exactVault {
		t.Fatalf("reference cookie does not represent the exact ordinary JIT graph: user=%t mailbox=%t account=%t member=%t factor=%t authority=%t vault=%t: %v",
			exactUser, exactMailbox, exactAccount, exactMember, exactFactor, exactAuthorities, exactVault, err)
	}
}
