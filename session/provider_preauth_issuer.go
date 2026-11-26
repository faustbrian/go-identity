package session

import (
	"strings"
	"time"
)

// NewProviderPreAuthIssuer selects the trusted One Tap callback provider for
// the original five-minute browser flow. It requires a configured HTTPS
// origin, no redirect, and the ordinary host-only pre-auth cookie. It runs no
// network or storage work. The independent durable executor must recognize
// this exact provider-bound profile before issuance can deliver a cookie.
func NewProviderPreAuthIssuer(executor PreAuthIssuanceExecutor, c PreAuthIssuerConfig, selected PreAuthProviderBinding) (*PreAuthIssuer, error) {
	intent := PreAuthIntent{Action: c.Action, CallbackURL: c.CallbackURL, Purpose: c.Purpose}
	if c.Cookie.name != "__Host-identity_flow" || c.FlowTTL != 5*time.Minute || !strings.HasPrefix(c.Origin, "https://") || !validProviderPreAuthProfile(intent, selected) {
		return nil, ErrInvalidIssuer
	}
	selected.ProviderID = strings.Clone(selected.ProviderID)
	selected.ClientID = strings.Clone(selected.ClientID)
	return newPreAuthIssuer(executor, c, FrontchannelCookiePolicy{}, selected)
}

func (s *PreAuthIssuer) newPreAuthRecord(spec PreAuthTransactionSpec) (PreAuthTransaction, error) {
	if s.provider.Mode == 0 {
		return NewPreAuthTransaction(spec)
	}
	return NewProviderPreAuthTransaction(ProviderPreAuthTransactionSpec{Transaction: spec, Provider: s.provider})
}

func (s *PreAuthIssuer) projectPreAuthRecord(record PreAuthTransaction) (PreAuthTransactionSpec, error) {
	if s.provider.Mode == 0 {
		return record.Bindings()
	}
	profile, err := record.ProviderBindings()
	if err != nil || profile.Provider != s.provider {
		return PreAuthTransactionSpec{}, ErrInvalidPreAuthTransaction
	}
	return profile.Transaction, nil
}

func (s *PreAuthIssuer) checkPreAuthRecord(record PreAuthTransaction, now time.Time, spec PreAuthTransactionSpec) error {
	if s.provider.Mode == 0 {
		return record.Check(now, spec.Binding, spec.Cookie)
	}
	return record.CheckProvider(now, spec.Binding, s.provider, spec.Cookie)
}
