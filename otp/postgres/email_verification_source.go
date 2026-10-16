package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// EmailVerificationSendDestination reads authenticated original keyed custody,
// or preliminary native pending state only when the key is authoritatively
// absent. It performs no preparation callback, writes, generation or delivery.
// The result is for transport budgets, never current admission. Same-key retry
// cannot be retargeted by a changed address or factor generation.
func (s *EmailVerificationService) EmailVerificationSendDestination(ctx context.Context, r otp.EmailVerificationSendRequest) (otp.DestinationInput, error) {
	if ctx == nil || s == nil || s.sender == nil || r.Validate() != nil {
		return otp.DestinationInput{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	originalSession, err := s.EmailVerificationSession(ctx, r.TenantID, r.Flow)
	if err != nil {
		return otp.DestinationInput{}, err
	}
	sessionBinding, err := originalSession.Bindings()
	if err != nil || sessionBinding.UserID != r.UserID {
		return otp.DestinationInput{}, identity.ForbiddenError{}
	}
	kind, id, bearer, _ := r.Flow.Bindings()
	request := sendInitiatingRequest{userID: r.UserID, flowKind: kind, flowID: id, purpose: otp.PurposeEmailVerification, channel: otp.ChannelEmail, addressID: r.AddressID, addressVersion: r.AddressVersion, network: r.Network, device: r.Device}
	p := s.sender.owner.store
	intent, err := p.sendRequestIntent(request, bearer)
	if err != nil {
		return otp.DestinationInput{}, err
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.sender.requestPolicyVersion)
	caller.Request.Action = "identity.otp.send"
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.send"}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, Method: "POST", RouteID: "identity.otp.send"}
	feature := kernel.FeatureRegistration{Contributor: s.sender.owner.Descriptor(), Operation: issuanceOperation(identity.FeatureSubjectUser)}
	b, wire, found, err := s.sender.coordinator.ReadPreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, feature, s.sender.owner)
	defer clear(wire)
	if err != nil {
		return otp.DestinationInput{}, err
	}
	if found {
		original, err := p.restoreSendInitiation(ctx, b, wire, bearer)
		if err != nil || original.suppressed || original.request.recipient == nil {
			return otp.DestinationInput{}, identity.ForbiddenError{}
		}
		continuation, err := original.request.continuation.Bindings()
		if err != nil {
			return otp.DestinationInput{}, ErrInvalidCommand
		}
		return continuation.Scope.Destination, nil
	}
	request, err = p.resolveEmailVerificationSend(ctx, identity.CommandBinding{TenantID: r.TenantID, UserID: r.UserID}, request)
	if err != nil {
		return otp.DestinationInput{}, err
	}
	return request.destination, nil
}

// EmailVerificationChallenge authenticates the original purpose/target/session
// before transport challenge budgets. Code is neither inspected nor retained.
// Executable current authority is checked without renewing original times;
// actual factor/target checks and metering remain inside the protected workflow.
func (s *EmailVerificationService) EmailVerificationChallenge(ctx context.Context, r otp.EmailVerifyRequest) (otp.EmailVerificationChallenge, error) {
	if ctx == nil || s == nil || s.sender == nil || r.Validate() != nil {
		return otp.EmailVerificationChallenge{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	original, custody, flow, err := s.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return otp.EmailVerificationChallenge{}, err
	}
	issued, err := custody.challenge.Bindings()
	if err != nil || custody.recipient == nil {
		return otp.EmailVerificationChallenge{}, identity.ForbiddenError{}
	}
	scope, err := issued.Continuation.Bindings()
	if err != nil || scope.Scope.Purpose != otp.PurposeEmailVerification || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.ChallengeID != string(r.SendCommandID) {
		return otp.EmailVerificationChallenge{}, identity.ForbiddenError{}
	}
	target, err := otp.ParseEmailVerificationTarget(scope.Scope.TargetID)
	if err != nil {
		return otp.EmailVerificationChallenge{}, err
	}
	selected, _ := target.Bindings()
	if selected.IdentifierID != custody.recipient.Identifier.ID {
		return otp.EmailVerificationChallenge{}, identity.ForbiddenError{}
	}
	f, _ := original.Feature()
	if err := s.source.requireCurrent(ctx, f.Binding, custody.authority, flow); err != nil {
		return otp.EmailVerificationChallenge{}, err
	}
	return otp.EmailVerificationChallenge{UserID: r.UserID, Target: target, Lifetime: issued.ExpiresAt.Sub(issued.IssuedAt)}, nil
}

var _ otp.EmailVerificationRateSource = (*EmailVerificationService)(nil)
