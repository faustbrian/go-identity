package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const ssoSAMLIDPLogoutPurpose = "identity.sso.saml-slo"
const ssoSAMLIDPLogoutSubjectType = "sso_saml_logout"

// MaxSSOSAMLIDPLogoutTargets bounds one atomic request. An adapter must reject
// overflow without truncating the selected sessions.
const MaxSSOSAMLIDPLogoutTargets = 128

// SSOSAMLIDPLogoutOperation admits a signed IdP-initiated logout request as a
// service command targeting one user. Its record identifies the original
// request transaction, not a browser session, and cannot settle a response.
func SSOSAMLIDPLogoutOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLIDPLogoutPurpose,
		SchemaID: "sso-enterprise-saml-idp-logout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// SSOSAMLIDPLogoutDescriptor selects the exact SSO-native request contributor.
func SSOSAMLIDPLogoutDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-logout", Version: 1}
}

// SSOSAMLIDPLogoutLifecycle creates one aggregate event for the request. The
// session owner still records each actual version transition in the same Work.
func SSOSAMLIDPLogoutLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "sso.saml_logout.revoked.v1", AfterVersion: 1}
}

// SSOSAMLIDPLogoutTarget identifies one current local session and its original
// SAML issuance. Version is the exact predecessor, not the revocation version.
type SSOSAMLIDPLogoutTarget struct {
	SessionID         string
	FamilyID          string
	IssuanceCommandID identity.CommandID
	Version           uint64
}

// SSOSAMLIDPLogoutIntent binds the pinned provider, digest of the authenticated
// original request, original exclusive UTC-microsecond cutoff, and complete
// session set. Targets are ordered by SessionID bytes without duplicates.
// Tenant and user come from the command binding. The synchronous caller must
// not mutate Targets during a call. This is not protocol or session evidence.
type SSOSAMLIDPLogoutIntent struct {
	OrganizationID string
	ProviderID     string
	RequestDigest  [32]byte
	ValidUntil     time.Time
	Targets        []SSOSAMLIDPLogoutTarget
}

const (
	samlIDPLogoutOrganization = "sso.saml.logout.organization"
	samlIDPLogoutProvider     = "sso.saml.logout.provider"
	samlIDPLogoutRequest      = "sso.saml.logout.request"
	samlIDPLogoutTargets      = "sso.saml.logout.targets"
	samlIDPLogoutUntil        = "sso.saml.logout.valid-until"
)

func invalidSSOSAMLIDPLogout() error {
	return identity.InvalidInputError{Field: "saml_idp_logout"}
}

// SSOSAMLIDPLogoutFields commits to the exact sorted target set without
// storing session IDs, SAML assertions, bearer credentials, or plaintext NameID
// in the feature fields. The trusted owner must verify the signed request and
// authorize its complete current target set separately. No IO occurs here.
func SSOSAMLIDPLogoutFields(intent SSOSAMLIDPLogoutIntent) ([]identity.FeatureField, error) {
	if !queryScopeText(intent.OrganizationID) || !queryScopeText(intent.ProviderID) || intent.RequestDigest == ([32]byte{}) ||
		!validSAMLIDPLogoutTime(intent.ValidUntil) || len(intent.Targets) == 0 || len(intent.Targets) > MaxSSOSAMLIDPLogoutTargets {
		return nil, invalidSSOSAMLIDPLogout()
	}
	var lastSession string
	issuances := make(map[identity.CommandID]struct{}, len(intent.Targets))
	encoded := make([][]byte, 0, len(intent.Targets))
	for _, target := range intent.Targets {
		if !queryScopeText(target.SessionID) || !queryScopeText(target.FamilyID) || target.SessionID <= lastSession || target.Version == 0 || target.Version == ^uint64(0) {
			return nil, invalidSSOSAMLIDPLogout()
		}
		if _, err := identity.ParseCommandID(string(target.IssuanceCommandID)); err != nil {
			return nil, invalidSSOSAMLIDPLogout()
		}
		if _, duplicate := issuances[target.IssuanceCommandID]; duplicate {
			return nil, invalidSSOSAMLIDPLogout()
		}
		issuances[target.IssuanceCommandID] = struct{}{}
		lastSession = target.SessionID
		encoded = append(encoded, cborArray([][]byte{cborText(target.SessionID), cborText(target.FamilyID), cborText(string(target.IssuanceCommandID)), cborUint(target.Version)}))
	}
	targetDigest := sha256.Sum256(cborArray([][]byte{cborText("sso-saml-idp-logout-targets-v1"), cborArray(encoded)}))
	return []identity.FeatureField{
		{Name: samlIDPLogoutOrganization, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.OrganizationID}},
		{Name: samlIDPLogoutProvider, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.ProviderID}},
		{Name: samlIDPLogoutRequest, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent.RequestDigest[:]}},
		{Name: samlIDPLogoutTargets, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: targetDigest[:]}},
		{Name: samlIDPLogoutUntil, Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: intent.ValidUntil.UTC()}},
	}, nil
}

func validSAMLIDPLogoutTime(t time.Time) bool {
	year := t.UTC().Year()
	return !t.IsZero() && year >= 1 && year <= 9999 && t.Nanosecond()%1000 == 0
}

func validSSOSAMLIDPLogoutBinding(b identity.CommandBinding) bool {
	return b.ValidateFor(SSOSAMLIDPLogoutOperation()) == nil && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(b.CommandID)
}

func validSSOSAMLIDPLogoutPlan(b identity.CommandBinding, p CommandPlan) bool {
	if !validSSOSAMLIDPLogoutBinding(b) || p.SubjectType != ssoSAMLIDPLogoutSubjectType || p.Lifecycle == nil || *p.Lifecycle != SSOSAMLIDPLogoutLifecycle() ||
		len(p.Audits) != 1 || p.Audits[0].EventType != ssoSAMLIDPLogoutPurpose || p.Audits[0].RetentionClass != "protected" || !p.Audits[0].Required {
		return false
	}
	return p.Capability == nil && p.CapabilityIssuance == nil && p.Delivery == nil && p.RiskEvidence == nil &&
		p.CommandCounters == nil && p.OTP == nil && p.CaptchaEvidence == nil && !p.CaptchaReplayReservation
}

func plainSSOSAMLIDPLogout(command identity.Command) bool {
	spec, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, bearer := command.SessionToken()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	if !ok || spec.Operation != SSOSAMLIDPLogoutOperation() || !validSSOSAMLIDPLogoutBinding(spec.Binding) || len(spec.Fields) != 5 || cookie || bearer || otp || recovery {
		return false
	}
	var zeroDigest [32]byte
	for _, field := range spec.Fields {
		v := field.Value
		switch field.Name {
		case samlIDPLogoutOrganization, samlIDPLogoutProvider:
			if v.Kind != identity.FeatureText || !queryScopeText(v.Text) {
				return false
			}
		case samlIDPLogoutRequest, samlIDPLogoutTargets:
			if v.Kind != identity.FeatureBytes || len(v.Bytes) != len(zeroDigest) || bytes.Equal(v.Bytes, zeroDigest[:]) {
				return false
			}
		case samlIDPLogoutUntil:
			if v.Kind != identity.FeatureTime || !validSAMLIDPLogoutTime(v.Time) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// RequireSSOSAMLIDPLogoutRequest fences the complete intent during the exact
// participant's original Apply or final check. Foreign, reconstructed, browser
// and preparation commands deny and poison live Work. The caller must still
// verify current provider and session authority, expiry, and the actual effect;
// this check performs no reads, revocation, or validity renewal.
func (w Work) RequireSSOSAMLIDPLogoutRequest(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, intent SSOSAMLIDPLogoutIntent) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	b, f, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !validSSOSAMLIDPLogoutBinding(b) || f.Operation != SSOSAMLIDPLogoutOperation() || f.Contributor != SSOSAMLIDPLogoutDescriptor() ||
		lifecycle != SSOSAMLIDPLogoutLifecycle() || w.state.subjectType != ssoSAMLIDPLogoutSubjectType || w.state.featurePreparationPlan != nil {
		return w.fail(ctx, invalidWork())
	}
	if w.state.featureApplying {
		if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
			return err
		}
	} else if w.state.featureReceipt == nil || w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return w.fail(ctx, invalidWork())
	}
	want, err := SSOSAMLIDPLogoutFields(intent)
	spec, ok := command.Feature()
	if err != nil || !ok || spec.Binding != b || !plainSSOSAMLIDPLogout(command) || !slices.EqualFunc(spec.Fields, want, equalSAMLIDPLogoutField) {
		return w.fail(ctx, invalidSSOSAMLIDPLogout())
	}
	return nil
}

func equalSAMLIDPLogoutField(a, b identity.FeatureField) bool {
	return a.Name == b.Name && a.Value.Kind == b.Value.Kind && a.Value.Text == b.Value.Text &&
		a.Value.Time.Equal(b.Value.Time) && bytes.Equal(a.Value.Bytes, b.Value.Bytes)
}
