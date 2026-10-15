package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

// EmailVerificationRequests returns the selected storage-neutral keyed add/resend
// port. It creates no HTTP route or resource. Calls join graph cancellation,
// require an allowed tenant and deny after Close; native custody remains owned
// by the graph. Unselected keyed workflows are unavailable.
func (f FeatureSet) EmailVerificationRequests() (email.VerificationSendService, error) {
	h, err := f.emailRequests(false)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// EmailChangeRequests returns the separately selected keyed change-request port.
// New-address confirmation and old-address notification remain native effects;
// this handle never promotes an address or silently selects a proof policy.
func (f FeatureSet) EmailChangeRequests() (email.ChangeRequestService, error) {
	h, err := f.emailRequests(true)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (f FeatureSet) emailRequests(change bool) (composedEmailRequests, error) {
	s := f.state
	if s == nil {
		return composedEmailRequests{}, identity.InvalidInputError{Field: "reference_email_requests"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.email == nil ||
		change && s.features.email.changeRequests == nil || !change && s.features.email.verificationRequests == nil {
		return composedEmailRequests{}, identity.UnavailableError{}
	}
	return composedEmailRequests{state: s, change: change}, nil
}

type composedEmailRequests struct {
	state  *storeState
	change bool
}

func (s composedEmailRequests) enter(ctx context.Context, tenant identity.TenantID, change bool) (context.Context, *passwordpg.EmailRequestWorkflow, func(), error) {
	if s.state == nil || s.change != change {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_email_requests"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	owner := s.state.features.email.verificationRequests
	if change {
		owner = s.state.features.email.changeRequests
	}
	return w, owner, done, nil
}

func (s composedEmailRequests) VerificationSendRateSource(ctx context.Context, r email.VerificationSendRequest) (identity.UserID, string, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID, false)
	if err != nil {
		return "", "", err
	}
	defer done()
	return owner.VerificationSendRateSource(w, r)
}

func (s composedEmailRequests) VerificationSend(ctx context.Context, r email.VerificationSendRequest) (email.VerificationSendResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID, false)
	if err != nil {
		return email.VerificationSendResult{}, err
	}
	defer done()
	return owner.VerificationSend(w, r)
}

func (s composedEmailRequests) ChangeRequestRateSource(ctx context.Context, r email.ChangeRequestRequest) (identity.UserID, string, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID, true)
	if err != nil {
		return "", "", err
	}
	defer done()
	return owner.ChangeRequestRateSource(w, r)
}

func (s composedEmailRequests) ChangeRequest(ctx context.Context, r email.ChangeRequestRequest) (email.ChangeRequestResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID, true)
	if err != nil {
		return email.ChangeRequestResult{}, err
	}
	defer done()
	return owner.ChangeRequest(w, r)
}

var _ email.VerificationSendService = composedEmailRequests{}
var _ email.ChangeRequestService = composedEmailRequests{}
