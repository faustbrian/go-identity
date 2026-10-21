package anonymous

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// SigninRequest carries original pre-auth possession and kernel retry custody.
// Tenant, caller, origin, network and device require trusted ingress provenance;
// they are not authentication or risk evidence. Remember is already resolved
// and must match the primary flow exactly. CallbackURL is the original selected
// callback, or empty for no redirect. No user, clock, lifetime or proof can be
// selected here. Keep caller collections immutable throughout the call. Native
// execution must admit current risk and atomically consume the original flow
// with identity/lifecycle/session effects under the existing kernel command.
type SigninRequest struct {
	TenantID       identity.TenantID
	PreAuthID      identity.PreAuthTransactionID
	Cookie         auth.BearerCredential
	Remember       session.RememberPolicy
	Origin         string
	CallbackURL    string
	Caller         authorization.DecisionContext
	Network        string
	Device         string
	IdempotencyKey identity.IdempotencyKey
}

// Validate checks bounded structure without IO, policy evaluation, time checks,
// cookie possession, key resolution or identity creation. URL allowlists and
// exact tenant/action/remember/original-flow agreement remain native-owner work.
// Zero is invalid. Successful validation grants no authority or bearer delivery.
func (r SigninRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || validateIngress(r.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil || r.CallbackURL != "" && !visibleText(r.CallbackURL, 2048) {
		return ErrInvalidInput
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.PreAuthID)); err != nil {
		return ErrInvalidInput
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return ErrInvalidInput
	}
	if _, err := r.Remember.Bindings(); err != nil {
		return ErrInvalidInput
	}
	return nil
}

// Ingress bounds apply before native intent framing or copying caller data.
// Canonical UTC metadata and IP text prevent multiple representations of one
// request identity; neither supplies authoritative time or risk admission.
func validateIngress(tenant identity.TenantID, caller authorization.DecisionContext, origin, network, device string) error {
	return validateIngressAction(tenant, caller, "identity.anonymous.signin", origin, network, device)
}

func validateIngressAction(tenant identity.TenantID, caller authorization.DecisionContext, action authorization.Action, origin, network, device string) error {
	r := caller.Request
	if !visibleText(string(tenant), 128) || r.Tenant != authorization.TenantID(tenant) || r.Action != action || !visibleText(string(r.Subject.ID), 128) || !visibleText(string(r.Resource.Type), 128) || r.Resource.ID != "" && !visibleText(string(r.Resource.ID), 128) || r.Environment.Time.Location() != time.UTC || len(r.Subject.Groups) > 64 {
		return ErrInvalidInput
	}
	switch r.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return ErrInvalidInput
	}
	for _, group := range r.Subject.Groups {
		if !visibleText(string(group), 128) {
			return ErrInvalidInput
		}
	}
	for _, attributes := range []authorization.Attributes{r.Attributes, r.Subject.Attributes, r.Resource.Attributes, r.Environment.Attributes} {
		if len(attributes) > 64 {
			return ErrInvalidInput
		}
		for name, value := range attributes {
			if !visibleText(string(name), 128) || value.Kind() == authorization.ValueMissing {
				return ErrInvalidInput
			}
			if text, ok := value.String(); ok && (len(text) > 4096 || !utf8.ValidString(text)) {
				return ErrInvalidInput
			}
			if address, ok := value.IP(); ok && address.Zone() != "" && !visibleText(address.Zone(), 128) {
				return ErrInvalidInput
			}
			if count, ok := value.CollectionLength(); ok {
				// The upstream accessor copies: bound cardinality before allocation.
				if count > 64 {
					return ErrInvalidInput
				}
				items, _ := value.StringSet()
				for _, text := range items {
					if len(text) > 4096 || !utf8.ValidString(text) {
						return ErrInvalidInput
					}
				}
			}
		}
	}
	if caller.Validate() != nil || !visibleText(origin, 2048) || !visibleText(network, 128) || device != "" && !visibleText(device, 128) {
		return ErrInvalidInput
	}
	address, err := netip.ParseAddr(network)
	if err != nil || address.Zone() != "" || address.String() != network {
		return ErrInvalidInput
	}
	return nil
}

func visibleText(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// SigninRecovery is immutable, credential-free original-command correlation,
// not current possession, disclosure permission or an executable retry. The
// namespace remains the original anonymous pre-auth flow, never its new user.
type SigninRecovery struct {
	query identity.RecoveryQuery
	flow  identity.PreAuthTransactionID
}

// NewSigninRecovery checks exact anonymous-signin/record-omitted shape only.
// Original cookie possession, retained input and current disclosure authority
// must be checked independently on the primary before exposing any history.
func NewSigninRecovery(q identity.RecoveryQuery, flow identity.PreAuthTransactionID) (SigninRecovery, error) {
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return SigninRecovery{}, ErrInvalidInput
	}
	if _, err := identity.ParsePreAuthTransactionID(string(flow)); err != nil {
		return SigninRecovery{}, ErrInvalidInput
	}
	if !visibleText(string(q.TenantID), 128) || !visibleText(string(q.ActorID), 128) || q.OperationID != "identity.anonymous.signin" || q.UserID != "" || q.AnonymousFlowID != string(flow) || q.RecordID != "" || q.LinkMode != 0 {
		return SigninRecovery{}, ErrInvalidInput
	}
	switch q.ActorKind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return SigninRecovery{}, ErrInvalidInput
	}
	return SigninRecovery{query: q, flow: flow}, nil
}

// Bindings projects scalar original correlation without renewing the flow or
// authorizing disclosure/execution. Explicit projections must not be logged.
func (r SigninRecovery) Bindings() (identity.RecoveryQuery, identity.PreAuthTransactionID, error) {
	if _, err := NewSigninRecovery(r.query, r.flow); err != nil {
		return identity.RecoveryQuery{}, "", err
	}
	return r.query, r.flow, nil
}

// SigninRecoveryRequest carries original cookie possession plus fresh trusted
// ingress metadata. It contains no retry key, selected user or fresh issuance.
// Recovery must not execute or re-evaluate risk, renew expiry or reveal tokens.
type SigninRecoveryRequest struct {
	Recovery SigninRecovery
	Cookie   auth.BearerCredential
	Caller   authorization.DecisionContext
	Origin   string
	Network  string
	Device   string
}

// Validate checks bounded shape and exact actor/tenant/action agreement only.
// Expired/consumed pre-auth rows do not erase retained recovery correlation.
func (r SigninRecoveryRequest) Validate() error {
	q, _, err := r.Recovery.Bindings()
	if err != nil || q.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || q.ActorKind != r.Caller.Request.Subject.Kind || validateIngress(q.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil {
		return ErrInvalidInput
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func (SigninRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.SigninRequest(redacted)"))
}
func (SigninRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (SigninRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (SigninRequest) LogValue() slog.Value {
	return slog.StringValue("anonymous.SigninRequest(redacted)")
}
func (SigninRecovery) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.SigninRecovery(redacted)"))
}
func (SigninRecovery) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (SigninRecovery) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (SigninRecovery) LogValue() slog.Value {
	return slog.StringValue("anonymous.SigninRecovery(redacted)")
}
func (SigninRecoveryRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.SigninRecoveryRequest(redacted)"))
}
func (SigninRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (SigninRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (SigninRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("anonymous.SigninRecoveryRequest(redacted)")
}
