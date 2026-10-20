package passwordpostgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// MFAPasswordPrimary is verified historical password-comparison provenance,
// not an AuthenticatedProof or session grant. Authority retains original signed
// security epochs; it is not a renewable current-validity lease. Completion must
// repeat directory, credential, policy, browser and factor fences in its sole
// protected Work before issuing a session. It contains no password or bearer.
type MFAPasswordPrimary struct {
	Authentication session.AuthenticationMetadata
	Authority      session.AuthoritySnapshot
	CommandID      identity.CommandID
	Recipient      kernel.RecipientRecord
}

// Format redacts correlated historical authentication metadata.
func (MFAPasswordPrimary) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.MFAPasswordPrimary(redacted)")
}

// MarshalJSON denies implicit primary metadata export.
func (MFAPasswordPrimary) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit textual metadata export.
func (MFAPasswordPrimary) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// LogValue redacts structured primary diagnostics.
func (MFAPasswordPrimary) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.MFAPasswordPrimary(redacted)")
}

// ReadMFAPasswordPrimary authenticates the exact issued child, frozen original
// challenge, non-final password signature and retained browser intent. It checks
// current directory, account, credential and authorization against the original
// signed epochs without replacing them. Child/primary expiry remains exclusive.
// The completion owner separately proves submitted cookie possession and repeats
// all current fences in Work; this read cannot consume a factor or issue a
// session. The borrowed primary pool and trusted policy have bounded lifetimes.
func (s *SigninService) ReadMFAPasswordPrimary(ctx context.Context, proof capability.Proof, continuation mfa.PartialAuthContinuation, flow session.PreAuthTransaction, caller authorization.DecisionContext) (MFAPasswordPrimary, error) {
	deny := func() (MFAPasswordPrimary, error) { return MFAPasswordPrimary{}, identity.ForbiddenError{} }
	if ctx == nil || s == nil || s.mfa == nil || caller.Validate() != nil {
		return deny()
	}
	ctx, stop := context.WithTimeout(ctx, s.c.Repository.MaximumDuration)
	defer stop()
	scope, err := continuation.Bindings()
	if err != nil {
		return deny()
	}
	grant, origin, _, err := s.mfa.issuer.ReadIssuanceOrigin(ctx, s.pool, proof, "identity.mfa.complete")
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	if continuation.Authorize(grant, s.mfa.config.IssuerURL, s.c.Issuance.Clock.Now()) != nil || string(scope.PrimaryProofID) != string(origin) || caller.Request.Tenant != authorization.TenantID(scope.TenantID) {
		return deny()
	}
	f, err := flow.Bindings()
	if err != nil || f.Binding.ID != scope.SourcePreAuthID || f.Binding.Intent.TenantID != scope.TenantID || f.Binding.Intent.Action != s.operation().OperationID || f.Binding.Intent.PolicyID != s.c.PolicyID || f.Binding.Intent.Origin != scope.Origin {
		return deny()
	}
	stored, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), s.c.Session, scope.TenantID, scope.SourcePreAuthID)
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	original, _ := stored.Bindings()
	suppliedRemember, re := f.Binding.Intent.Remember.Bindings()
	originalRemember, oe := original.Binding.Intent.Remember.Bindings()
	wantedRemember, we := scope.RememberPolicy.Bindings()
	if re != nil || oe != nil || we != nil || suppliedRemember != originalRemember || wantedRemember != originalRemember {
		return deny()
	}
	f.Binding.Intent.Remember = original.Binding.Intent.Remember
	if f != original {
		return deny()
	}
	q := identity.RecoveryQuery{CommandID: origin, TenantID: scope.TenantID, AnonymousFlowID: string(scope.SourcePreAuthID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: s.operation().OperationID}
	disclosure := caller.Clone()
	disclosure.PolicyRevision = authorization.Revision(s.c.Coordinator.QueryPolicy.PolicyVersion)
	disclosure.Request.Action = authorization.Action(s.operation().OperationID)
	disclosure.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	p := &signinMFAChallengePhase{service: s}
	coordinator, _, err := s.mfaCoordinator(p)
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	expected, record, present, err := coordinator.QueryPasswordMFAChallenge(ctx, q, disclosure)
	digest, derr := continuation.ScopeDigest()
	if err != nil || derr != nil || !present || record.Outcome != identity.CommitOutcomeCommitted || expected.ID != identity.CommandID(scope.ID) || expected.UserID != identity.UserID(scope.SubjectID) || expected.ScopeDigest != digest || expected.PolicyVersion != scope.PolicyVersion || expected.FactorVersion != scope.FactorVersion || !expected.IssuedAt.Equal(scope.IssuedAt) || !expected.ExpiresAt.Equal(scope.ExpiresAt) {
		return deny()
	}
	cmd, err := base64.RawURLEncoding.Strict().DecodeString(string(origin))
	if err != nil {
		return deny()
	}
	var wire, storedDigest []byte
	err = s.pool.Raw().QueryRow(ctx, `SELECT CASE WHEN octet_length(record)<=$4 THEN record ELSE ''::bytea END,record_digest FROM identity_password.mfa_primary_records WHERE tenant_id=$1 AND user_id=$2 AND command_id=$3 AND purpose=$6 AND proof_id=$5`, string(scope.TenantID), string(scope.SubjectID), cmd, maximumSigninRecordBytes, string(origin), s.operation().OperationID).Scan(&wire, &storedDigest)
	defer clear(wire)
	if err != nil {
		return MFAPasswordPrimary{}, readerFailure(ctx)
	}
	primary, sum, err := decodeMFASigninPrimary(wire, s.c.VerificationKeys, s.c.Issuer, s.c.Environment, scope.PrimaryProofID, string(scope.TenantID), string(scope.SubjectID))
	if err != nil || primary.Profile != s.mfaPrimaryProfile() || len(storedDigest) != 32 || subtle.ConstantTimeCompare(storedDigest, sum[:]) != 1 || sum != scope.PrimaryProofDigest || !primary.Proof.IssuedAt.Equal(scope.IssuedAt) || !primary.Proof.ExpiresAt.Equal(scope.PrimaryProofExpiresAt) {
		return deny()
	}
	now := s.c.Issuance.Clock.Now()
	if continuation.RequirePending(now) != nil || primary.Proof.Validate(auth.ProofUse{Tenant: string(scope.TenantID), Subject: string(scope.SubjectID), Audience: s.c.Profile.Audience, Purpose: session.PasswordMFAPrimaryPurpose, Now: now}) != nil {
		return deny()
	}
	a := primary.Authority
	directory, err := s.domain.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.c.Profile.GlobalAuthorityID, TenantID: scope.TenantID})
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	credential, err := s.domain.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: scope.TenantID, UserID: identity.UserID(scope.SubjectID), CredentialID: identity.CredentialID(primary.CredentialID)})
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	ref := identity.CredentialRef{ID: identity.CredentialID(primary.CredentialID), TenantID: scope.TenantID, UserID: identity.UserID(scope.SubjectID), Kind: identity.CredentialPassword, Owner: "identity/password", Version: primary.CredentialVersion}
	identifiers, err := s.domain.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: scope.TenantID, UserID: ref.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	policy, err := s.policyAuthority.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(scope.TenantID), SubjectID: authorization.SubjectID(scope.SubjectID), PolicyNamespace: s.c.Profile.PolicyNamespace})
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	now = s.c.Issuance.Clock.Now()
	if !directory.Enabled || directory.GlobalVersion != a.Global.Version || directory.TenantVersion != a.Tenant.Version || identity.CheckCredentialAuthority(credential, ref, a.Credential.Version, now) != nil || identifiers.AuthorityVersion != a.Identifier.Version || credential.User.Status != identity.StatusActive || identifiers.User.Status != identity.StatusActive || policy.Version != a.Authorization.Version {
		return deny()
	}
	status, err := s.domain.GetStatus(ctx, identity.UserStatusQuery{TenantID: scope.TenantID, UserID: ref.UserID})
	if err != nil {
		return MFAPasswordPrimary{}, err
	}
	if status.AuthorityVersion != a.User.Version || status.User.Status != identity.StatusActive || continuation.RequirePending(s.c.Issuance.Clock.Now()) != nil {
		return deny()
	}
	kind := identity.IdentifierEmail
	if s.c.Phone != nil {
		kind = identity.IdentifierPhone
	}
	var recipient kernel.RecipientRecord
	for j, identifier := range identifiers.Identifiers {
		if identifier.ID != primary.IdentifierID {
			continue
		}
		if identifier.Kind != kind || identifier.Version != primary.IdentifierVersion || identifiers.Verifications[j].Version != primary.VerificationVersion {
			return deny()
		}
		query := kernel.RecipientQuery{TenantID: scope.TenantID, Kind: kind, CanonicalValue: identifier.CanonicalValue, Eligibility: kernel.RecipientVerified}
		if s.c.Phone != nil {
			profile := s.c.Phone.Profile()
			query.NormalizationProfile, query.NormalizationVersion = profile.ID, profile.Version
		}
		recipient, err = s.domain.ResolveRecipient(ctx, query)
		if err != nil {
			return MFAPasswordPrimary{}, err
		}
		break
	}
	if recipient.Validate() != nil || recipient.Suppressed || recipient.User.ID != ref.UserID || recipient.Identifier.ID != primary.IdentifierID || recipient.Identifier.Version != primary.IdentifierVersion || recipient.Verification.Version != primary.VerificationVersion || recipient.UserAuthorityVersion != a.User.Version || recipient.IdentifierAuthorityVersion != a.Identifier.Version || recipient.CredentialAuthorityVersion != a.Credential.Version {
		return deny()
	}
	authority, err := session.NewAuthoritySnapshot(a)
	if err != nil {
		return deny()
	}
	return MFAPasswordPrimary{CommandID: origin, Recipient: recipient, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: primary.Proof, ProofVersion: primary.ProofVersion, CredentialID: primary.CredentialID, CredentialVersion: primary.CredentialVersion}, Authority: authority}, nil
}
