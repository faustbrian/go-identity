package passwordpostgres

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MFAVerificationPrimary is authenticated historical email-possession origin,
// not password proof, completed MFA or a session grant. Signup, confirmation
// and challenge are distinct. Authority preserves the original observed epochs;
// completion must repeat account, identifier, policy, browser and factor fences
// under its sole protected Work. No reusable primary bearer is retained here.
type MFAVerificationPrimary struct {
	CommandID, SignupCommandID, VerificationCommandID identity.CommandID
	Authentication                                    session.MagicLinkAuthentication
	Authority                                         session.AuthoritySnapshot
	Recipient                                         kernel.RecipientRecord
	Parent                                            issuerpg.MFAVerificationParent
}

// Format hides correlated historical custody.
func (MFAVerificationPrimary) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.MFAVerificationPrimary(redacted)"))
}

// MarshalJSON denies implicit origin export.
func (MFAVerificationPrimary) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit textual custody export.
func (MFAVerificationPrimary) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// LogValue redacts structured diagnostics.
func (MFAVerificationPrimary) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.MFAVerificationPrimary(redacted)")
}

// ReadMFAVerificationPrimary authenticates the exact child, original pending
// scope and separately consumed registration parent, then reads the original
// encrypted challenge output through current authorized history access. It
// reconstructs no primary credential and never signs or discloses replacements.
// Current preliminary authority must match the original epochs; completion must
// repeat those fences atomically. Flow comes from native original browser state,
// not client-projected Remember. All IO shares the original bounded timeout and
// earlier cancellation. The pool is borrowed; no transaction/goroutine is owned.
func (s *VerificationSigninService) ReadMFAVerificationPrimary(ctx context.Context, proof capability.Proof, continuation mfa.PartialAuthContinuation, flow session.PreAuthTransaction, caller authorization.DecisionContext) (out MFAVerificationPrimary, err error) {
	deny := func() (MFAVerificationPrimary, error) { return MFAVerificationPrimary{}, identity.ForbiddenError{} }
	if ctx == nil || s == nil || s.signup == nil || s.mfa == nil || caller.Validate() != nil {
		return deny()
	}
	ctx, stop := context.WithTimeout(ctx, s.signup.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = MFAVerificationPrimary{}
		}
	}()
	scope, err := continuation.Bindings()
	if err != nil || scope.VerificationCommandID == "" || caller.Request.Tenant != authorization.TenantID(scope.TenantID) {
		return deny()
	}
	grant, origin, _, err := s.mfa.issuer.ReadIssuanceOrigin(ctx, s.signup.pool, proof, "identity.mfa.complete")
	if err != nil {
		return out, err
	}
	if continuation.Authorize(grant, s.mfa.config.IssuerURL, s.c.Issuance.Clock.Now()) != nil || grant.Payload().CorrelationID != string(scope.VerificationCommandID) {
		return deny()
	}
	parent, err := s.mfa.issuer.ReadMFAVerificationParent(ctx, s.signup.pool, proof, string(scope.PrimaryProofID), scope.PrimaryProofDigest, scope.PrimaryProofExpiresAt)
	if err != nil {
		return out, err
	}
	bindings, err := parent.Bindings()
	if err != nil || bindings.ChallengeCommandID != origin || bindings.VerificationCommandID != scope.VerificationCommandID || bindings.UserID != identity.UserID(scope.SubjectID) || bindings.TenantID != scope.TenantID {
		return deny()
	}
	q := identity.RecoveryQuery{CommandID: origin, TenantID: scope.TenantID, UserID: identity.UserID(scope.SubjectID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, RecordID: string(scope.VerificationCommandID), OperationID: "identity.email.verification-signin"}
	disclosure := caller.Clone()
	disclosure.PolicyRevision = authorization.Revision(s.signup.config().Coordinator.QueryPolicy.PolicyVersion)
	disclosure.Request.Action = authorization.Action(q.OperationID)
	disclosure.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}
	p := &verificationMFAChallengePhase{service: s}
	coordinator, _, err := s.mfaCoordinator(p)
	if err != nil {
		return out, err
	}
	expected, record, present, err := coordinator.QueryEmailVerificationMFAChallenge(ctx, q, disclosure)
	digest, digestErr := continuation.ScopeDigest()
	if err != nil || digestErr != nil || !present || record.Outcome != identity.CommitOutcomeCommitted || expected.ID != identity.CommandID(scope.ID) || expected.UserID != q.UserID || expected.ScopeDigest != digest || expected.PolicyVersion != scope.PolicyVersion || expected.FactorVersion != scope.FactorVersion || !expected.IssuedAt.Equal(scope.IssuedAt) || !expected.ExpiresAt.Equal(scope.ExpiresAt) {
		return deny()
	}
	wire, generation, err := coordinator.QueryFeaturePreparation(ctx, q, disclosure, p.registration(), p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	stored, err := s.readVerificationMFAOutput(ctx, record.Binding, generation, wire)
	if err != nil {
		return out, err
	}
	defer clear(stored.Checkpoint)
	storedScope := mfa.ContinuationSpec(stored.Scope)
	storedScope.RememberPolicy, err = session.NewRememberPolicy(stored.Flow.Remember)
	if err != nil {
		return deny()
	}
	original, err := mfa.NewPartialAuthContinuation(storedScope)
	if err != nil {
		return deny()
	}
	originalDigest, err := original.ScopeDigest()
	if err != nil || originalDigest != digest || stored.PrimaryEnvelope != scope.PrimaryProofDigest || parent.MatchPayload(capability.Payload(stored.Primary)) != nil {
		return deny()
	}
	originalFlow, err := signupFlowState(stored.Flow)
	if err != nil {
		return deny()
	}
	supplied, err := signupFlowProjection(flow)
	if err != nil || supplied != stored.Flow || stored.Flow.Action != "identity.password.signup" || stored.Flow.ID != scope.SourcePreAuthID || stored.Flow.Origin != scope.Origin {
		return deny()
	}
	flowSpec, _ := originalFlow.Bindings()
	wantedRemember, rememberErr := scope.RememberPolicy.Bindings()
	if rememberErr != nil || wantedRemember != stored.Flow.Remember || !flowSpec.Binding.ExpiresAt.After(s.c.Issuance.Clock.Now()) {
		return deny()
	}
	issuance := kernel.CapabilityIssuancePlan{Contributor: stored.Issuer, MFAContinuationUserID: q.UserID, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(stored.Grant)}}
	if issuance.Grants[0].ProofFingerprint != grant.EnvelopeDigest() || issuance.Grants[0].CapabilityID != string(scope.ID) {
		return deny()
	}
	if _, err := s.mfa.codec.RestorePreparation(ctx, record.Binding, generation, issuance, stored.Checkpoint); err != nil {
		return deny()
	}
	m := stored.Metadata
	if m.CommandID != origin || m.RequestCommandID != bindings.RequestCommandID || m.CapabilityID != bindings.CapabilityID || string(m.IdentifierID) != capability.Payload(stored.Primary).Resource || !m.AuthenticatedAt.Equal(scope.IssuedAt) || !m.ValidUntil.Equal(scope.PrimaryProofExpiresAt) {
		return deny()
	}
	metadata, err := session.NewMagicLinkAuthentication(m)
	if err != nil {
		return deny()
	}
	identifiers, err := s.signup.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: q.TenantID, UserID: q.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return out, err
	}
	var recipient kernel.RecipientRecord
	for _, identifier := range identifiers.Identifiers {
		if identifier.ID != m.IdentifierID {
			continue
		}
		if identifier.Kind != identity.IdentifierEmail || identifier.Version != m.IdentifierVersion {
			return deny()
		}
		recipient, err = s.signup.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: q.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: identifier.CanonicalValue, Eligibility: kernel.RecipientVerified})
		if err != nil {
			return out, err
		}
		break
	}
	a := stored.Authority
	if recipient.Validate() != nil || recipient.Suppressed || recipient.User.ID != q.UserID || recipient.Identifier.ID != m.IdentifierID || recipient.Identifier.Version != m.IdentifierVersion || recipient.Verification.Version != m.VerificationVersion || recipient.UserAuthorityVersion != a.User.Version || recipient.IdentifierAuthorityVersion != a.Identifier.Version || recipient.CredentialAuthorityVersion != a.Credential.Version {
		return deny()
	}
	directory, err := s.signup.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.c.Profile.GlobalAuthorityID, TenantID: q.TenantID})
	if err != nil {
		return out, err
	}
	policy, err := s.policy.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), SubjectID: authorization.SubjectID(q.UserID), PolicyNamespace: s.c.Profile.PolicyNamespace})
	if err != nil {
		return out, err
	}
	if !directory.Enabled || directory.GlobalVersion != a.Global.Version || directory.TenantVersion != a.Tenant.Version || policy.Version != a.Authorization.Version || continuation.RequirePending(s.c.Issuance.Clock.Now()) != nil {
		return deny()
	}
	authority, err := session.NewAuthoritySnapshot(a)
	if err != nil {
		return deny()
	}
	if !reflect.DeepEqual(scope.AllowedMethods, []string{"totp"}) {
		return deny()
	}
	return MFAVerificationPrimary{CommandID: origin, SignupCommandID: bindings.RequestCommandID, VerificationCommandID: bindings.VerificationCommandID, Authentication: metadata, Authority: authority, Recipient: recipient, Parent: parent}, nil
}
