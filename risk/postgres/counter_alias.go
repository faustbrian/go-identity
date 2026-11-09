package postgres

import (
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PrepareCommandCountersWithRetainedKeys reconstructs original feature counter
// intent using authenticated retained key-version metadata, original subject
// and original primary time. It performs no IO, allowance or reservation.
// Versions must be 1..4 distinct newest-first retained aliases, not an inbound
// request's choice. The real repository remains the enlisted current owner:
// ReserveCommandCounters still rejects a new charge missing current aliases.
func (r *Repository) PrepareCommandCountersWithRetainedKeys(c identity.Command, subject risk.Subject, at time.Time, versions []uint32) (identity.Command, kernel.CommandCounterPlan, error) {
	retained, err := r.withRetainedCounterKeys(versions)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	return retained.PrepareCommandCounters(c, subject, at)
}

// PrepareAccountLinkPreparationCountersWithRetainedKeys preserves original
// callback/session intent and nonrenewing time after key rotation. Only actual
// retained aliases are accepted. Obtain versions from the original durable risk
// charge after authenticating the original flow/browser, never from HTTP input.
// This pure reconstruction grants no provider, state, charge or link authority;
// the actual current repository must enforce admission in the sole root Work.
func (r *Repository) PrepareAccountLinkPreparationCountersWithRetainedKeys(spec identity.AccountLinkPreparationCommand, input identity.OAuthCallbackInput, bearer authentication.BearerCredential, subject risk.Subject, at time.Time, versions []uint32) (identity.Command, kernel.CommandCounterPlan, error) {
	retained, err := r.withRetainedCounterKeys(versions)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	return retained.PrepareAccountLinkPreparationCounters(spec, input, bearer, subject, at)
}

func (r *Repository) withRetainedCounterKeys(versions []uint32) (*Repository, error) {
	if r == nil || r.counters == nil || len(versions) < 1 || len(versions) > 4 {
		return nil, risk.ErrInvalidCounterCommand
	}
	keys := make([]risk.CounterDigestKey, 0, len(versions))
	for i, v := range versions {
		if v == 0 || i > 0 && versions[i-1] <= v {
			return nil, risk.ErrInvalidCounterCommand
		}
		found := false
		for _, k := range r.counters.Keys {
			if k.Version() == v {
				keys = append(keys, k)
				found = true
				break
			}
		}
		if !found {
			return nil, risk.ErrInvalidCounterCommand
		}
	}
	cfg := risk.CommandCounterPolicyConfig{Policy: r.counters.Policy, Keys: keys}
	policy, err := risk.NewCommandCounterPolicy(cfg)
	if err != nil {
		return nil, risk.ErrInvalidCounterCommand
	}
	copy := *r
	copy.counters, copy.counterPolicy = &cfg, policy
	return &copy, nil
}
