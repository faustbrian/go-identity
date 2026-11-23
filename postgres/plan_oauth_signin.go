package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

type providerSigninConsumptionProfile struct {
	Contrib          ContributorDescriptor
	SubjectType      string
	AuditEvent       string
	AuditRetention   string
	WireTag          string
	Lifecycle        LifecyclePlan
	ExternalRiskOnly bool
}

func providerSigninProfile(op identity.FeatureOperation) (providerSigninConsumptionProfile, bool) {
	switch op {
	case oauthSigninAccountOperation():
		return providerSigninConsumptionProfile{
			Contrib:     ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1},
			SubjectType: "authentication_attempt", AuditEvent: "identity.oauth.handle_callback", AuditRetention: "protected", WireTag: "identity-oauth-signin-consumption-v1",
			Lifecycle: LifecyclePlan{EventType: "session.created.v1"},
		}, true
	case ssoOIDCSigninOperation():
		return providerSigninConsumptionProfile{
			Contrib:     ssoOIDCSigninDescriptor(),
			SubjectType: "sso_login_transaction", AuditEvent: "identity.sso.login", AuditRetention: "protected", WireTag: "identity-sso-oidc-signin-consumption-v1", ExternalRiskOnly: true,
			Lifecycle: LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2},
		}, true
	case SSOOAuth2SigninOperation():
		return providerSigninConsumptionProfile{
			Contrib:     ssoOAuth2SigninDescriptor(),
			SubjectType: "sso_login_transaction", AuditEvent: "identity.sso.login", AuditRetention: "protected", WireTag: "identity-sso-oauth2-signin-consumption-v1", ExternalRiskOnly: true,
			Lifecycle: LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2},
		}, true
	case SSOSAMLSigninOperation():
		return providerSigninConsumptionProfile{
			Contrib:     ssoSAMLSigninDescriptor(),
			SubjectType: "sso_login_transaction", AuditEvent: "identity.sso.login", AuditRetention: "protected", WireTag: "identity-sso-saml-signin-consumption-v1", ExternalRiskOnly: true,
			Lifecycle: LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2},
		}, true
	case SSOSAMLIDPConfirmationOperation():
		return providerSigninConsumptionProfile{
			Contrib: ssoSAMLIDPConfirmationDescriptor(), SubjectType: "sso_saml_confirmation",
			AuditEvent: "identity.sso.login", AuditRetention: "protected", WireTag: "identity-sso-saml-idp-confirmation-consumption-v1", ExternalRiskOnly: true,
			Lifecycle: LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2},
		}, true
	case SSOOIDCExplicitLinkCallbackOperation():
		return providerSigninConsumptionProfile{
			Contrib:     ssoOIDCSigninDescriptor(),
			SubjectType: "sso_login_transaction", AuditEvent: "identity.account.link", AuditRetention: "standard", WireTag: "identity-sso-oidc-explicit-link-consumption-v1", ExternalRiskOnly: true,
			Lifecycle: LifecyclePlan{EventType: "enterprise_provider.account_linked.v1", BeforeVersion: 1, AfterVersion: 2},
		}, true
	default:
		return providerSigninConsumptionProfile{}, false
	}
}

func providerSigninConsumptionOperation(op identity.FeatureOperation) bool {
	_, selected := providerSigninProfile(op)
	return selected
}

func providerSigninBindingOperation(b identity.CommandBinding) (identity.FeatureOperation, bool) {
	for _, op := range [...]identity.FeatureOperation{oauthSigninAccountOperation(), ssoOIDCSigninOperation(), SSOOAuth2SigninOperation(), SSOSAMLSigninOperation(), SSOSAMLIDPConfirmationOperation(), SSOOIDCExplicitLinkCallbackOperation()} {
		if b.OperationID == op.OperationID && b.SchemaID == op.SchemaID {
			return op, true
		}
	}
	return identity.FeatureOperation{}, false
}

func providerSigninPreparation(p CommandPlan) bool {
	if p.Feature == nil || p.Capability == nil || p.Capability.MaxUses != 1 {
		return false
	}
	profile, ok := providerSigninProfile(p.Feature.Operation)
	return ok && p.Feature.Contributor == profile.Contrib && p.Capability.Purpose == capability.Purpose(p.Feature.Operation.OperationID)
}

// Only this fixed-depth envelope admits callback-state consumption for native
// existing-account signin. Provider exchange and session effects remain owned
// by the native contributor, not by a second coordinator or replay authority.
func encodeProviderSigninConsumptionPlan(b identity.CommandBinding, fingerprint [32]byte, p CommandPlan) ([]byte, error) {
	capabilityOwner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || p.Capability == nil || p.Lifecycle == nil {
		return nil, invalidPlan()
	}
	profile, selected := providerSigninProfile(p.Feature.Operation)
	if !selected || !providerSigninPreparation(p) || profile.ExternalRiskOnly && p.CommandCounters != nil {
		return nil, invalidPlan()
	}
	if !validProviderConsumptionBinding(b, p.Feature.Operation) {
		return nil, invalidPlan()
	}
	if p.SubjectType != profile.SubjectType || validateCapabilityPlan(b, p.Capability) != nil || *p.Lifecycle != profile.Lifecycle {
		return nil, invalidPlan()
	}
	owners := 5
	if p.CommandCounters != nil {
		owners++
	}
	if len(p.Contributors) != owners || p.Contributors[owners-1] != capabilityOwner || len(p.Audits) != 1 {
		return nil, invalidPlan()
	}
	if p.Audits[0].EventType != profile.AuditEvent || p.Audits[0].RetentionClass != profile.AuditRetention {
		return nil, invalidPlan()
	}
	unselectedAuthentication := p.APIKeyVerification != nil || p.MFACompletion != nil || p.MFAContinuation != nil || p.MagicLinkRegistration != nil || p.PasskeyRegistration != nil || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.IdentifierAdmission != nil
	unselectedEffects := p.OrganizationInvitationOrigin != nil || p.Delivery != nil || p.CapabilityIssuance != nil || p.AccountLinkState != nil || p.OTP != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation
	if unselectedAuthentication || unselectedEffects {
		return nil, invalidPlan()
	}
	base := p
	base.Capability = nil
	base.Contributors = p.Contributors[:owners-1]
	wire, err := encodeFeaturePlanMode(b, fingerprint, base, true)
	if err != nil {
		return nil, err
	}
	encoded := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText(profile.WireTag), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(capabilityOwner.Owner), "contract_id": cborText(capabilityOwner.ContractID), "version": cborUint(uint64(capabilityOwner.Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func validProviderConsumptionBinding(b identity.CommandBinding, operation identity.FeatureOperation) bool {
	if operation == SSOOIDCExplicitLinkCallbackOperation() {
		return validSSOOIDCExplicitLinkBinding(b)
	}
	if operation == SSOSAMLIDPConfirmationOperation() {
		return validSSOSAMLIDPConfirmationBinding(b)
	}
	return b.ValidateFor(operation) == nil && b.ActorKind == authorization.SubjectServiceAccount && b.UserID == "" && b.AnonymousFlowID != ""
}

func decodeProviderSigninConsumptionPlan(b identity.CommandBinding, fingerprint [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	op, selected := providerSigninBindingOperation(b)
	if !selected {
		return fail()
	}
	profile, _ := providerSigninProfile(op)
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	count, ok := r.head(2)
	// A single ordinary counter/feature base is allowed, never another envelope.
	if !r.ok || !ok || count == 0 || count > uint64(len(r.data)) || r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fingerprint, r.data[:int(count)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(count):]
	r.key("profile")
	r.consume(cborText(profile.WireTag))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	proof := &CapabilityPlan{Purpose: capability.Purpose(op.OperationID)}
	r.key("purpose")
	r.consume(cborText(string(proof.Purpose)))
	r.key("max_uses")
	proof.MaxUses = uint32(r.number(math.MaxUint32))
	r.key("expires_at")
	proof.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	r.key("capability_id")
	proof.CapabilityID = r.string(256)
	r.key("replay_digest")
	r.digest(&proof.ReplayDigest)
	r.key("proof_fingerprint")
	r.digest(&proof.ProofFingerprint)
	r.key("replay_key_version")
	proof.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
	r.key("contributor")
	owner := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.Capability = proof
	base.Contributors = append(base.Contributors, owner)
	canonical, err := encodeProviderSigninConsumptionPlan(b, fingerprint, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
