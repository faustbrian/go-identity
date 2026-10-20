package passwordpostgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

// Only the native coordinator's acknowledged generation may enter this
// preparation. Original signed scope and consumption come from actual issuance
// custody; current authority and distinct completion RiskEvidence remain the
// phase's responsibility. PrepareProtected owns HIBP/provider assessment and
// hashing, deferring only native-owned velocity. No risk evaluation, OTP/TOTP
// comparison, proof consumption, SQL, journal or permission is created here.
func (r *Repository) generatePhoneResetCommand(ctx context.Context, input identity.Command, c password.HashPreparationConfig, verifier capability.Service, profile password.ResetProfile, original password.ResetGrantSpec, grant capability.Grant, consumption kernel.CapabilityPlan, collect ResetScreeningCollector) (command identity.Command, facts []risk.Signal, err error) {
	caller := ctx
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if caller != nil && caller.Err() != nil {
			err = caller.Err()
		}
		if err != nil {
			command, facts = identity.Command{}, nil
		}
	}()
	spec, metadata := input.PhonePasswordResetInputFeature()
	candidate, proof, sms, totp, custody := input.PhonePasswordResetInputCustody()
	cookie, present := input.PhonePasswordResetPreAuthCookie()
	if ctx == nil || r == nil || r.policy.Algorithm() == "" || !metadata || !custody || !present || candidate.Len() == 0 || verifier == nil || c.Now == nil || c.Timeout <= 0 || c.Timeout > 10*time.Second || original.FactorVersion == 0 {
		return command, nil, password.ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return command, nil, err
	}
	intent, err := passwordResetIntent(spec)
	if err != nil || spec.Operation != phonePasswordResetOperation() {
		return command, nil, password.ErrPasswordWork
	}
	if err := passwordResetOriginalIntent(intent, profile, original, grant, consumption, c.Now()); err != nil {
		return command, nil, err
	}
	// Reverify the actual borrowed proof before any provider/hash work; a grant
	// with matching scalar predecessors cannot authorize another envelope.
	payload := grant.Payload()
	if len(payload.Audiences) != 1 || payload.Operation != spec.Binding.OperationID {
		return command, nil, identity.ForbiddenError{}
	}
	verified, err := verifier.Verify(ctx, proof, capability.Purpose(spec.Binding.OperationID), payload.Audiences[0])
	if err != nil || verified.EnvelopeDigest() != grant.EnvelopeDigest() {
		return command, nil, identity.ForbiddenError{}
	}
	if collect != nil {
		challenge := verified.Payload().ID
		if c.Collect != nil || challenge == "" || challenge != consumption.CapabilityID {
			return command, nil, password.ErrPasswordWork
		}
		c.Collect = func(ctx context.Context, actual risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
			return collect(ctx, spec.Binding, challenge, actual, borrowed)
		}
	}
	provider := c.Collect
	if provider == nil {
		return command, nil, password.ErrPasswordWork
	}
	c.Collect = func(ctx context.Context, actual risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
		collected, err := provider(ctx, actual, borrowed)
		if err != nil || len(collected) == 0 || len(collected) > 32 {
			return nil, password.ErrPasswordWork
		}
		facts = slices.Clone(collected)
		return slices.Clone(facts), nil
	}
	preparer, err := password.NewHashPreparer(c)
	if err != nil {
		return command, nil, err
	}
	scope := risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}
	hash, _, err := preparer.PrepareProtected(ctx, candidate, scope)
	if err != nil {
		return command, nil, err
	}
	command, err = identity.NewFeaturePhonePasswordResetCommand(spec, hash.String(), proof, sms, totp)
	if err == nil {
		command, err = identity.BindPhonePasswordResetPreAuth(command, cookie)
	}
	if err != nil {
		return command, nil, password.ErrPasswordWork
	}
	// Provider/hash latency must not renew the grant or original predecessors.
	if _, _, err := passwordResetOriginalMaterial(command, r.policy, profile, original, verified, consumption, c.Now()); err != nil {
		return command, nil, err
	}
	return command, slices.Clone(facts), nil
}
