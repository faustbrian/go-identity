package mfapostgres

import (
	"context"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// ActiveStepUpRateSource authenticates current native session/CSRF and confirmed
// encrypted factor custody without decrypting secrets, comparing codes, issuing
// proof or reserving/debiting an attempt. It returns the fixed startup step-up
// policy lifetime and earliest original primary/session deadline, not a renewed
// lease. TotpVerify independently checks current authority and atomic effects.
func (s *TOTPActiveStepUpService) ActiveStepUpRateSource(ctx context.Context, r mfa.TotpVerifyRequest) (lifetime time.Duration, until time.Time, err error) {
	if ctx == nil || s == nil || s.state == nil || r.StepUp == nil || r.Validate() != nil {
		return 0, time.Time{}, invalidAuthority()
	}
	state := s.state()
	if !slices.Contains(state.config.AllowedOrigins, r.Origin) || r.StepUp.Purpose == "identity.email.change-request" && !state.config.EmailChange {
		return 0, time.Time{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			lifetime, until = 0, time.Time{}
		}
	}()
	if err = authorizeNativeMFAAction(ctx, state.shared, r.Caller, "identity.mfa.totp-verify"); err != nil {
		return 0, time.Time{}, err
	}
	primary, observed, err := state.config.Primary.PrepareStepUp(ctx, r)
	if err != nil {
		return 0, time.Time{}, err
	}
	active, err := state.reader.ReadForStepUp(ctx, observed, string(r.FactorID))
	if err != nil {
		return 0, time.Time{}, err
	}
	meta, err := active.Metadata()
	if err != nil {
		return 0, time.Time{}, err
	}
	until, err = primary.Deadline()
	if err != nil {
		return 0, time.Time{}, err
	}
	if meta.ValidUntil.Before(until) {
		until = meta.ValidUntil
	}
	if !time.Now().Before(until) {
		return 0, time.Time{}, identity.ForbiddenError{}
	}
	return state.config.TTL, until, nil
}
