package passwordpostgres

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
)

// EvaluatePasswordResetCompletionRisk authenticates the actual canonical grant,
// committed SMS request and original recovery browser before resolving the
// account/phone/factor for distinct completion-only evidence. No caller supplies
// a user, number, carrier fact or risk verdict. Original issuance retries retain
// the same reference and absolute expiry without provider re-evaluation.
//
// This does not compare codes, consume the grant or change a password/session.
// Completion must independently fence and consume all actual owners in its sole
// Work. The borrowed input/pool remain caller-owned; earlier deadlines win.
func (s *PhonePasswordResetRequestService) EvaluatePasswordResetCompletionRisk(ctx context.Context, request phone.PasswordResetCompletionRiskRequest) (out risk.PhoneEvidenceResult, err error) {
	if ctx == nil || s == nil || s.read == nil {
		return out, password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return out, err
	}
	native := s.read()
	ctx, cancel := context.WithTimeout(ctx, native.primary.c.Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = risk.PhoneEvidenceResult{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			out, err = risk.PhoneEvidenceResult{}, ctx.Err()
		}
	}()
	grant, command, _, err := native.link.issuer.ReadIssuanceOrigin(ctx, native.primary.pool, r.ResetCapability, "identity.phone.password-reset-complete")
	if err != nil {
		return out, err
	}
	origin, err := native.link.profile.ResolveOriginal(grant, time.Now().UTC())
	if err != nil || origin.TenantID != r.TenantID || origin.OriginCommandID != command || r.CommandID == command || r.IssuanceCommandID == command {
		return out, identity.ForbiddenError{}
	}
	stored, _, _, err := native.readOriginalRateSource(ctx, origin, r.Caller, r.Flow)
	defer clear(stored.FactorEnvelope)
	if err != nil {
		return out, err
	}
	if r.Origin != stored.Flow.Origin {
		return out, identity.ForbiddenError{}
	}
	admission, err := newPhonePasswordRecoveryRisk(native.primary.pool, native.c.Risk, r.Caller, origin.UserID)
	if err != nil {
		return out, err
	}
	intent := phoneResetCompletionRiskIntent(r, origin, stored.Recipient.Query.CanonicalValue, string(stored.Flow.ID), stored.Flow.Identifier)
	// Recovery must precede live admission: the original successful reset has
	// consumed its browser/factors and advanced the password epoch. The risk
	// owner's exact historical resolution neither renews evidence nor evaluates
	// providers. Historical metadata is never executable reset authority.
	recovered, err := admission.issuer.Recover(ctx, intent)
	if err != nil || recovered.Outcome != risk.EvidenceMissing {
		return recovered, err
	}
	coordinator, err := native.coordinator(&phoneResetKeyPhase{service: native}, nil)
	if err != nil {
		return out, err
	}
	caller := r.Caller.Clone()
	caller.Request.Resource.ID = authorization.ResourceID(origin.UserID)
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: origin.UserID, RecordID: string(origin.CredentialID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: phonePasswordResetOperation().OperationID}
	observed, err := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if err != nil {
		return out, err
	}
	if observed.Validate() != nil || !observed.Absent {
		// A different issuance ID cannot start providers for a consuming command
		// that already exists, even if its original browser is still live.
		return out, identity.ForbiddenError{}
	}
	if _, err = native.restoreIssuedRequest(ctx, origin, r.Caller, r.Flow); err != nil {
		return out, err
	}
	return admission.issuer.Evaluate(ctx, intent)
}

func phoneResetCompletionOriginalRisk(r phone.PasswordResetCompletionRiskRequestSpec, original *phoneResetIssuedRequest) risk.PhoneEvidenceRequest {
	f, _ := original.source.flow.Bindings()
	return phoneResetCompletionRiskIntent(r, original.origin, original.source.recipient.Query.CanonicalValue, string(f.Binding.ID), f.Binding.Intent.IdentifierBinding)
}

func phoneResetCompletionRiskIntent(r phone.PasswordResetCompletionRiskRequestSpec, origin password.ResetGrantSpec, number, flow string, identifier [32]byte) risk.PhoneEvidenceRequest {
	return risk.PhoneEvidenceRequest{CommandID: string(r.IssuanceCommandID), Actor: string(r.Caller.Request.Subject.ID), Recovery: risk.CarrierRequest{Phase: risk.PhoneResetCompletion, Binding: risk.PhoneRecoveryScope{Tenant: string(r.TenantID), Subject: string(origin.UserID), RecoveryOperation: "identity.phone.password-reset-complete", CanonicalNumber: number, PreAuthTransaction: flow, Attempt: string(r.CommandID), PolicyVersion: origin.Phone.RiskPolicyVersion}}, Subject: risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(identifier[:])}}
}
