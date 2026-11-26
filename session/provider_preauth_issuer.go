package session

import (
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// OneTapStartPreAuthOperation identifies the exact Google One Tap start that
// can commit the pre-authentication flow. It conveys no execution authority.
func OneTapStartPreAuthOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-start",
		SchemaID: "oauth-onetap-start-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
}

// NewProviderPreAuthIssuer selects the trusted One Tap callback provider for
// the original five-minute browser flow. It requires a configured HTTPS
// origin, no redirect, and the ordinary host-only pre-auth cookie. It runs no
// network or storage work. The independent durable executor must recognize
// this exact provider-bound profile before issuance can deliver a cookie.
func NewProviderPreAuthIssuer(executor PreAuthIssuanceExecutor, c PreAuthIssuerConfig, selected PreAuthProviderBinding) (*PreAuthIssuer, error) {
	return newProviderPreAuthIssuer(executor, c, selected, PreAuthIssueOperation())
}

// NewOneTapStartPreAuthIssuer selects the Google callback flow and its exact
// One Tap start commit. The issuer rejects a generic pre-auth issuance receipt
// even for the same original flow. The executor must own keyed start and all
// mandatory effects; this constructor neither executes nor replaces that work.
func NewOneTapStartPreAuthIssuer(executor PreAuthIssuanceExecutor, c PreAuthIssuerConfig, selected PreAuthProviderBinding) (*PreAuthIssuer, error) {
	if selected.ProviderID != "google" {
		return nil, ErrInvalidIssuer
	}
	return newProviderPreAuthIssuer(executor, c, selected, OneTapStartPreAuthOperation())
}

// PrepareOneTapStart generates the session-owned nonce and cookie for an
// exact server-selected Google One Tap binding. Only a One Tap start issuer
// accepts it. The durable executor calls it after admitting the keyed start
// and passes the original binding, never an ID or policy selected by the
// browser. The record and anonymous flow ID must be identical and canonical.
// No durable work occurs here; only Issue can release the cookie after an
// exact new receipt. Retain the original preparation and never regenerate on
// replay, recovery or unknown commitment.
func (s *PreAuthIssuer) PrepareOneTapStart(binding identity.CommandBinding, remember RememberPolicy) (PreparedPreAuthIssuance, error) {
	if s == nil || s.operation != OneTapStartPreAuthOperation() || binding.RecordID != binding.AnonymousFlowID {
		return PreparedPreAuthIssuance{}, ErrInvalidIssuance
	}
	id, err := identity.ParsePreAuthTransactionID(binding.AnonymousFlowID)
	if err != nil {
		return PreparedPreAuthIssuance{}, ErrInvalidIssuance
	}
	input := PreAuthPrepareInput{CommandID: binding.CommandID, TenantID: binding.TenantID, CorrelationID: binding.CorrelationID, Remember: remember}
	return s.prepare(input, id, &binding)
}

func newProviderPreAuthIssuer(executor PreAuthIssuanceExecutor, c PreAuthIssuerConfig, selected PreAuthProviderBinding, operation identity.FeatureOperation) (*PreAuthIssuer, error) {
	intent := PreAuthIntent{Action: c.Action, CallbackURL: c.CallbackURL, Purpose: c.Purpose}
	if selected.Mode != PreAuthProviderCallback || c.Cookie.name != "__Host-identity_flow" || c.FlowTTL != 5*time.Minute || !strings.HasPrefix(c.Origin, "https://") || !validProviderPreAuthProfile(intent, selected) {
		return nil, ErrInvalidIssuer
	}
	selected.ProviderID = strings.Clone(selected.ProviderID)
	selected.ClientID = strings.Clone(selected.ClientID)
	return newPreAuthIssuer(executor, c, FrontchannelCookiePolicy{}, selected, operation)
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
