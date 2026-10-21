package anonymouspostgres

import (
	"context"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// SigninRateSource authenticates the original pre-auth possession and intent
// before returning its stable HTTP rate dimension. It reads only the primary
// original flow and performs no identity lookup, admission, command preparation,
// risk evaluation, entropy or mutation. The returned value is not an identifier
// supplied by the browser and must never be logged or treated as authority.
//
// Retained consumed/expired flows keep this rate scope for keyed retries, not
// permission to create another guest. Signin independently enforces live flow
// admission for a new command; only its existing owner can recover old work.
// Calls are bounded, concurrency-safe and preserve redacted error identities.
func (s *SigninService) SigninRateSource(ctx context.Context, r anonymous.SigninRequest) (source string, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return "", anonymous.ErrInvalidInput
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			source = ""
			err = signinPublicError(ctx, err)
		}
	}()
	if !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.CallbackURLs, r.CallbackURL) {
		return "", identity.ForbiddenError{}
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), c.Sessions, r.TenantID, r.PreAuthID)
	if err != nil {
		return "", err
	}
	p := signinPhase{service: s, request: r}
	// Historical possession checks the original binding/digest without minting
	// a new validity lease. Only protected fresh execution admits its lifetime.
	if _, err = p.admitFlow(flow, time.Time{}, true); err != nil {
		return "", err
	}
	return "anonymous-flow:" + string(r.PreAuthID), nil
}

// DeletionRateSource authenticates original anonymous credential and CSRF
// possession before returning its rate subject. Retained revoked sessions
// select only the same historical retry scope, never active authority. Delete
// independently admits live state for new work and original-command policy for
// replay. No command, retention callback, risk effect or mutation occurs here.
// The value is internal routing metadata, not public identity disclosure or a
// reusable proof. Borrowed dependencies retain their bounded concurrent owners.
func (s *DeletionService) DeletionRateSource(ctx context.Context, r anonymous.DeletionRequest) (user identity.UserID, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return "", anonymous.ErrInvalidInput
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			user = ""
			err = signinPublicError(ctx, err)
		}
	}()
	if !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.Reasons, r.Reason) {
		return "", identity.ForbiddenError{}
	}
	source, err := s.retainedSource(ctx, r)
	if err != nil {
		return "", err
	}
	spec, err := source.Bindings()
	if err != nil {
		return "", err
	}
	return spec.UserID, nil
}
