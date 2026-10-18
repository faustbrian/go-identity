package passwordpostgres

import (
	"context"
	"slices"
	"time"

	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

// Native signup selects the Authentication lane, not ReserveWithCommand. Its
// original admission already owns counter and decision-audit identity. Borrow
// those signed facts unchanged and collect only the owned HIBP adapter's fact;
// collecting a second complete evaluation would charge velocity twice. The
// keyed preparation journal owns whether generation may run, not this helper.
// Returned facts belong only in that owner's authenticated encrypted output.
func (*Repository) prepareSignupHash(ctx context.Context, c password.HashPreparationConfig, original risk.AuthenticationAdmission, scope risk.Context, candidate primitive.Secret) (hash primitive.EncodedHash, facts []risk.Signal, err error) {
	if scope.Operation != "identity.password.signup" && scope.Operation != "identity.username.signup" {
		return hash, nil, password.ErrPasswordWork
	}
	return prepareAuthenticationHash(ctx, c, original, scope, candidate, scope.Operation)
}

// Reset and signup share the canonical Authentication lane. The exact action
// remains bound to original custody; sharing screening cannot turn one
// operation's counted admission into authority for the other.
func (*Repository) prepareResetHash(ctx context.Context, c password.HashPreparationConfig, original risk.AuthenticationAdmission, scope risk.Context, candidate primitive.Secret) (primitive.EncodedHash, []risk.Signal, error) {
	return prepareAuthenticationHash(ctx, c, original, scope, candidate, "identity.password.reset-complete")
}

func prepareAuthenticationHash(ctx context.Context, c password.HashPreparationConfig, original risk.AuthenticationAdmission, scope risk.Context, candidate primitive.Secret, action risk.Action) (hash primitive.EncodedHash, facts []risk.Signal, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			hash, facts = primitive.EncodedHash{}, nil
		}
	}()
	if ctx == nil || c.Collect == nil || c.Now == nil {
		return hash, nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return hash, nil, err
	}
	p := original.Prepared()
	if (action != "identity.password.signup" && action != "identity.username.signup" && action != "identity.password.reset-complete") || scope.Operation != action || scope.Tenant != p.Scope.Tenant || scope.Operation != p.Scope.Operation || scope.Attempt != p.Scope.Attempt || scope.IndependentFactor != p.Scope.IndependentFactor || len(p.Signals) == 0 || len(p.Signals) > 31 {
		return hash, nil, password.ErrPasswordWork
	}
	admission, err := c.Policy.Admit(scope.Operation)
	if err != nil || admission.PolicyVersion != p.PolicyVersion || admission.Profile.Class != risk.Authentication {
		return hash, nil, password.ErrPasswordWork
	}
	for _, fact := range p.Signals {
		if fact.Name == "hibp" {
			return hash, nil, password.ErrPasswordWork
		}
	}
	if err := original.Check(ctx); err != nil {
		return hash, nil, password.ErrPasswordWork
	}
	collect := c.Collect
	c.Collect = func(ctx context.Context, actual risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
		if actual.Now.IsZero() || actual.Now.Before(p.Scope.Now) {
			return nil, password.ErrPasswordWork
		}
		if err := original.Check(ctx); err != nil {
			return nil, password.ErrPasswordWork
		}
		if err := original.CheckAt(ctx, actual.Now); err != nil {
			return nil, password.ErrPasswordWork
		}
		provider, err := collect(ctx, actual, borrowed)
		if err != nil || len(provider) != 1 || provider[0].Name != "hibp" {
			return nil, password.ErrPasswordWork
		}
		if err := original.Check(ctx); err != nil {
			return nil, password.ErrPasswordWork
		}
		facts = append(slices.Clone(p.Signals), provider[0])
		return slices.Clone(facts), nil
	}
	preparer, err := password.NewHashPreparer(c)
	if err != nil {
		return hash, nil, err
	}
	// No password, provider response or mutable callback state enters admission
	// custody. The preparer checks byte bounds before Collect, then assesses these
	// complete original facts both before and after cryptographic work.
	hash, _, err = preparer.Prepare(ctx, candidate, scope)
	if err != nil {
		return hash, nil, err
	}
	if err := original.Check(ctx); err != nil {
		return hash, nil, password.ErrPasswordWork
	}
	if err := checkAuthenticationScreening(ctx, c.Policy, p.Scope, facts, c.Now(), action); err != nil {
		return hash, nil, err
	}
	return hash, slices.Clone(facts), nil
}

// Final native commit checks supply primary time rather than invoking a clock
// callback under SQL locks. Authentication custody must already have been
// authenticated outside Work; these immutable facts cannot be renewed here.
// This does not establish current flow/account/field authority or one-time use.
func checkSignupScreening(ctx context.Context, policy risk.Policy, original risk.Context, facts []risk.Signal, now time.Time) error {
	if original.Operation != "identity.password.signup" && original.Operation != "identity.username.signup" {
		return password.ErrPasswordWork
	}
	return checkAuthenticationScreening(ctx, policy, original, facts, now, original.Operation)
}

func (*Repository) checkResetScreening(ctx context.Context, policy risk.Policy, original risk.Context, facts []risk.Signal, now time.Time) error {
	return checkAuthenticationScreening(ctx, policy, original, facts, now, "identity.password.reset-complete")
}

func checkAuthenticationScreening(ctx context.Context, policy risk.Policy, original risk.Context, facts []risk.Signal, now time.Time, action risk.Action) error {
	if ctx == nil || now.IsZero() || now.Before(original.Now) || (action != "identity.password.signup" && action != "identity.username.signup" && action != "identity.password.reset-complete") || original.Operation != action {
		return password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	original.Now = now
	result, err := policy.Assess(ctx, original, facts)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || result.Decision.Action != risk.Allow {
		return password.ErrPasswordWork
	}
	return nil
}
