package password

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// SigninRequest preserves borrowed raw password and actual original pre-auth
// cookie possession. It is trusted direct-platform input, not a wire schema.
// TenantID, Caller, Origin, Network and Device require trusted composition
// provenance; none is authentication evidence. Identifier is unnormalized;
// its configured owner must canonicalize it before native account discovery.
// Remember is already resolved and must match the original primary flow exactly.
// CallbackURL is the exact selected callback, or empty for explicit no redirect.
// It cannot replace the original flow's callback or configured allowlist.
//
// Signin is non-keyed: the native service creates each attempt's command ID,
// never accepting a caller retry key or automatically resubmitting after unknown
// commitment. No request field selects a user, proof, assurance, clock or expiry.
// Treat Caller collections and the entire request as immutable during calls.
// Password remains caller-owned; destroy it after return, never normalize it.
// Do not log/persist explicit field projections, which bypass redaction methods.
type SigninRequest struct {
	TenantID    identity.TenantID
	PreAuthID   identity.PreAuthTransactionID
	Cookie      auth.BearerCredential
	Identifier  identifier.Input
	Password    primitive.Secret
	Remember    session.RememberPolicy
	Origin      string
	CallbackURL string
	Caller      authorization.DecisionContext
	Network     string
	Device      string
}

// Validate checks bounded structure only. It performs no IO, password borrow,
// hashing, normalization, proof validation or authoritative time/state check.
// Cookie parsing checks canonical session-owned token syntax, not possession
// against the primary record. Origin/callback admission here checks bounded
// visible ASCII only; the native owner must validate URL/profile/allowlist and
// exact original intent, including tenant/action/remember/policy/timeline.
// Native primary admission must also enforce current caller, account, credential,
// risk and factor policy. Success grants no authentication or issuance authority.
// Zero values deny; a live-secret length observation is not a custody lease.
// Caller evaluation time must have the canonical UTC location (including zero),
// not retained caller-selected timezone data. It is not authoritative time.
// Collection bounds constrain logical content/work, not the storage capacity of
// already constructed caller-owned containers or immutable upstream values.
func (r SigninRequest) Validate() error {
	if validateSigninProvenance(r.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil || (r.CallbackURL != "" && !verificationText(r.CallbackURL, 2048)) || r.Password.Len() == 0 || r.Password.Len() > 1<<20 {
		return ErrPasswordWork
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.PreAuthID)); err != nil {
		return ErrPasswordWork
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return ErrPasswordWork
	}
	if _, err := identifier.NewInput(string(r.Identifier)); err != nil {
		return ErrPasswordWork
	}
	if _, err := r.Remember.Bindings(); err != nil {
		return ErrPasswordWork
	}
	return nil
}

// Recovery and new login share the same trusted caller/input bounds, without
// recovery needing a password, identifier or live executable pre-auth record.
func validateSigninProvenance(tenant identity.TenantID, caller authorization.DecisionContext, origin, network, device string) error {
	c := caller.Request
	if c.Environment.Time.Location() != time.UTC || len(c.Attributes) > 64 || len(c.Subject.Groups) > 64 || len(c.Subject.Attributes) > 64 || len(c.Resource.Attributes) > 64 || len(c.Environment.Attributes) > 64 {
		return ErrPasswordWork
	}
	for _, group := range c.Subject.Groups {
		if !boundedChangeText(string(group)) {
			return ErrPasswordWork
		}
	}
	for _, attributes := range []authorization.Attributes{c.Attributes, c.Subject.Attributes, c.Resource.Attributes, c.Environment.Attributes} {
		for name, value := range attributes {
			if !boundedChangeText(string(name)) || value.Kind() == authorization.ValueMissing {
				return ErrPasswordWork
			}
			if text, ok := value.String(); ok && (len(text) > 4096 || !utf8.ValidString(text)) {
				return ErrPasswordWork
			}
			if address, ok := value.IP(); ok && address.Zone() != "" && !boundedChangeText(address.Zone()) {
				return ErrPasswordWork
			}
			if count, ok := value.CollectionLength(); ok {
				// StringSet returns a copy: reject cardinality before allocating it.
				if count > 64 {
					return ErrPasswordWork
				}
				items, _ := value.StringSet()
				for _, text := range items {
					if len(text) > 4096 || !utf8.ValidString(text) {
						return ErrPasswordWork
					}
				}
			}
		}
	}
	if !boundedChangeText(string(tenant)) || !boundedChangeText(string(c.Subject.ID)) || !boundedChangeText(string(c.Action)) || !boundedChangeText(string(c.Resource.Type)) || (c.Resource.ID != "" && !boundedChangeText(string(c.Resource.ID))) || c.Tenant != authorization.TenantID(tenant) || caller.Validate() != nil || !boundedChangeText(network) || (device != "" && !boundedChangeText(device)) || !verificationText(origin, 2048) {
		return ErrPasswordWork
	}
	switch c.Subject.Kind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return ErrPasswordWork
	}
	address, err := netip.ParseAddr(network)
	if err != nil || address.Zone() != "" || address.String() != network {
		return ErrPasswordWork
	}
	return nil
}

// Format redacts all input custody and correlation for every diagnostic verb.
func (SigninRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SigninRequest(redacted)")
}

// MarshalJSON denies implicit export; optional transport owns its wire schema.
func (SigninRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies text and map-key export of original sensitive custody.
func (SigninRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a constant marker without any submitted input or correlation.
func (SigninRequest) LogValue() slog.Value {
	return slog.StringValue("password.SigninRequest(redacted)")
}
