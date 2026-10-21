package anonymous

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Upgrader composes actual target authentication, guest possession, a typed
// merge plan and the public capability/session owners. The protected mutation
// consumes the target action proof and original one-use grant atomically with
// the guest transition and session replacement. Unknown requires reconciliation
// of both original commands, not a new upgrade or regenerated grant.
type Upgrader interface {
	Upgrade(context.Context, UpgradeRequest) (UpgradeResult, error)
	RecoverUpgrade(context.Context, UpgradeRecoveryRequest) (UpgradeResult, error)
}

// UpgradeRequest borrows two distinct original credentials. TargetProof is
// caller-supplied structure, not authority: the password owner must
// authenticate its signed committed record and consume it in the protected
// transaction. Guest possession never proves permanent-account ownership.
// Both synchronizer tokens and single-factor password reauthentication are
// required by this selected profile; other target methods remain unsupported.
//
// Plan supplies explicit proposed scope/decisions; the native owner compares
// its source with actual guest lifecycle and its target with the authenticated
// permanent identity. Unsupported transfers deny before mutation. Remember must
// equal both original selected policies; requests cannot extend either lifetime.
// Caller/Origin/Network/Device require trusted ingress provenance. Keep inputs
// unchanged until the bounded call returns. Never serialize or log this value.
type UpgradeRequest struct {
	TenantID       identity.TenantID
	TargetSession  auth.BearerCredential
	TargetProof    auth.ReauthenticationProof
	TargetCSRF     session.CSRFToken
	Guest          session.Credential
	GuestCSRF      session.CSRFToken
	Plan           MergePlan
	Remember       session.RememberPolicy
	Caller         authorization.DecisionContext
	Origin         string
	Network        string
	Device         string
	IdempotencyKey identity.IdempotencyKey
}

// Validate checks bounded structure only, without IO, clock, authentication,
// proof consumption or granting merge/session authority. Existing canonical
// permanent identifiers are preserved; only the anonymous source is opaque.
func (r UpgradeRequest) Validate() error {
	p, err := r.Plan.Validated()
	if err != nil {
		return ErrInvalidInput
	}
	s, _ := p.Source.Record()
	if s.TenantID != r.TenantID || r.Caller.Request.Subject.Kind != authorization.SubjectUser || string(r.Caller.Request.Subject.ID) != string(p.Target) || r.Caller.Request.Resource.Type != "anonymous" || string(r.Caller.Request.Resource.ID) != string(s.UserID) || validateIngressAction(r.TenantID, r.Caller, "identity.anonymous.upgrade", r.Origin, r.Network, r.Device) != nil {
		return ErrInvalidInput
	}
	if validateUpgradePossession(r.TenantID, r.TargetSession, r.TargetCSRF, r.Guest, r.GuestCSRF, r.Origin, r.Network, r.Device) != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return ErrInvalidInput
	}
	if _, err := r.Remember.Bindings(); err != nil {
		return ErrInvalidInput
	}
	proof := r.TargetProof
	// ReauthenticationService issues identity.password.verify proofs whose
	// independent Action names the protected mutation. Conflating those two
	// bindings would reject the actual password owner's signed records.
	if proof.Action != "identity.anonymous.upgrade" || proof.Proof.Purpose != "identity.password.verify" || proof.Proof.Method != "password" || proof.Proof.Assurance != auth.AssuranceSingleFactor || proof.Proof.Tenant != string(r.TenantID) || proof.Proof.Subject != string(p.Target) || !visibleText(proof.SessionID, 128) || proof.SessionVersion == 0 {
		return ErrInvalidInput
	}
	if _, err := auth.NewProof(auth.ProofSpec(proof.Proof)); err != nil {
		return ErrInvalidInput
	}
	return nil
}

// UpgradeResult retains both original command correlations, including Unknown.
// Preparation is the internal durable issuance command; Recovery identifies the
// protected upgrade. Session and CSRFToken are delivered only for the exact new,
// known committed execution while original authority is still valid. Replay and
// recovery return metadata only, never another credential or renewed deadline.
type UpgradeResult struct {
	Outcome     identity.CommitOutcome
	Preparation identity.RecoveryQuery
	Recovery    identity.RecoveryQuery
	Session     session.IssueResult
	CSRFToken   session.CSRFToken
	Replayed    bool
	RetryAfter  time.Duration
}

// UpgradeRecoveryRequest presents original possession for both identities,
// including a self-revoked guest. It can disclose only attributable metadata;
// it cannot reactivate either session, renew a proof or start another mutation.
type UpgradeRecoveryRequest struct {
	Preparation             identity.RecoveryQuery
	Recovery                identity.RecoveryQuery
	TargetSession           auth.BearerCredential
	TargetCSRF              session.CSRFToken
	Guest                   session.Credential
	GuestCSRF               session.CSRFToken
	Origin, Network, Device string
}

// Validate checks original correlation and bounded custody, never current
// authority, durable outcomes or permission to disclose another command.
func (r UpgradeRecoveryRequest) Validate() error {
	p, q := r.Preparation, r.Recovery
	if _, err := identity.ParseCommandID(string(p.CommandID)); err != nil {
		return ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return ErrInvalidInput
	}
	if _, err := identity.ParseSubjectID(q.RecordID); err != nil {
		return ErrInvalidInput
	}
	if p.OperationID != "identity.anonymous.upgrade" || q.OperationID != p.OperationID || p.CommandID == q.CommandID || p.TenantID != q.TenantID || p.UserID != q.UserID || p.ActorID != q.ActorID || p.ActorKind != q.ActorKind || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) || string(q.UserID) == q.RecordID || p.RecordID != "" || p.AnonymousFlowID != "" || q.AnonymousFlowID != "" || p.LinkMode != 0 || q.LinkMode != 0 || (identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}).Validate(q.TenantID) != nil {
		return ErrInvalidInput
	}
	return validateUpgradePossession(q.TenantID, r.TargetSession, r.TargetCSRF, r.Guest, r.GuestCSRF, r.Origin, r.Network, r.Device)
}

func validateUpgradePossession(tenant identity.TenantID, target auth.BearerCredential, targetCSRF session.CSRFToken, guest session.Credential, guestCSRF session.CSRFToken, origin, network, device string) error {
	if _, err := session.ParseToken(target.Token()); err != nil || targetCSRF == (session.CSRFToken{}) {
		return ErrInvalidInput
	}
	return validateAnonymousPossession(tenant, guest, guestCSRF, origin, network, device)
}

func (UpgradeRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.UpgradeRequest(redacted)"))
}
func (UpgradeRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (UpgradeRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (UpgradeRequest) LogValue() slog.Value {
	return slog.StringValue("anonymous.UpgradeRequest(redacted)")
}
func (UpgradeResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.UpgradeResult(redacted)"))
}
func (UpgradeResult) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (UpgradeResult) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (UpgradeRecoveryRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.UpgradeRecoveryRequest(redacted)"))
}
func (UpgradeRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (UpgradeRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
