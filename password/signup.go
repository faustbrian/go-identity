package password

import (
	"fmt"
	"io"
	"log/slog"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// SignupRequest borrows the exact raw password, original pre-auth cookie and
// retry-key custody. Email is generic unnormalized address input despite its
// compatibility name: the configured registration owner, not this package,
// interprets and canonicalizes it. AllowedFields contains untrusted requested
// values, not field-policy approval; the identity owner must admit the whole
// set against its frozen schema before hashing or mutation.
//
// TenantID, Caller, Origin, Network and Device require trusted composition
// provenance. RememberPolicy is already resolved and must match the original
// primary flow. CallbackURL is the exact selected callback, or empty for an
// explicit no-redirect policy. The native owner validates these against primary
// flow intent and configured allowlists. No caller-selected subject, command
// identity, clock, assurance or password verifier is accepted. IdempotencyKey
// selects an original scoped attempt through the kernel's existing mapping;
// it must never be logged, returned or replaced after an unknown outcome.
//
// Keep the request and all Caller/AllowedFields collections immutable during
// use. Password remains caller-owned; destroy it only after the call returns.
// Do not log explicit field projections, which bypass diagnostic redaction.
type SignupRequest struct {
	TenantID  identity.TenantID
	PreAuthID identity.PreAuthTransactionID
	Cookie    auth.BearerCredential
	Email     SignupAddressInput
	// Username is raw supplementary input only for identity.username.signup.
	// Empty preserves the legacy password-signup profile. The selected native
	// username policy must normalize/validate and atomically reserve it alongside
	// Email; this transport field provides neither ownership nor availability.
	Username       string
	Password       primitive.Secret
	AllowedFields  []identity.AttributeUpdate
	RememberPolicy session.RememberPolicy
	Origin         string
	CallbackURL    string
	Caller         authorization.DecisionContext
	Network        string
	Device         string
	IdempotencyKey identity.IdempotencyKey
}

// Validate checks bounded structure only, without IO, hashing, password borrow,
// normalization, attribute approval, authoritative time or key correlation.
// Success is not permission to create an account, admit a flow or issue a
// session. Native policy must validate the exact original input independently.
func (r SignupRequest) Validate() error {
	action := authorization.Action("identity.password.signup")
	if r.Username != "" {
		action = "identity.username.signup"
		if len(r.Username) > 128 || !utf8.ValidString(r.Username) {
			return ErrPasswordWork
		}
	}
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || r.Caller.Request.Action != action || r.Email.Validate() != nil || !validSignupFields(r.AllowedFields) {
		return ErrPasswordWork
	}
	// Reuse the shared original-flow transport/provenance boundary without
	// interpreting the address as an identifier or invoking any policy callback.
	if validateSigninProvenance(r.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil || r.CallbackURL != "" && !verificationText(r.CallbackURL, 2048) || r.Password.Len() == 0 || r.Password.Len() > 1<<20 {
		return ErrPasswordWork
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.PreAuthID)); err != nil {
		return ErrPasswordWork
	}
	if _, err := session.ParseToken(r.Cookie.Token()); err != nil {
		return ErrPasswordWork
	}
	if _, err := r.RememberPolicy.Bindings(); err != nil {
		return ErrPasswordWork
	}
	return nil
}

// Transport limits are stricter in field count than the general identity
// processor. Schema existence, output/sensitivity/write policy and permitted
// defaults still belong to that processor, not this structural input check.
func validSignupFields(fields []identity.AttributeUpdate) bool {
	if len(fields) > 64 {
		return false
	}
	total := 0
	for i, field := range fields {
		name := field.Name
		if len(name) == 0 || len(name) > 128 || name[0] < 'a' || name[0] > 'z' || name == "id" || name == "tenant_id" || name == "status" || name == "version" {
			return false
		}
		for _, c := range []byte(name) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
		for _, previous := range fields[:i] {
			if previous.Name == name {
				return false
			}
		}
		value := field.Value
		if value.Kind == identity.AttributeStringList {
			if value.Scalar != (identity.AttributeScalar{}) || value.List == nil || len(value.List) > 64 {
				return false
			}
			for _, scalar := range value.List {
				if scalar.Kind != identity.AttributeString || !validSignupScalar(scalar) || len(scalar.String) > (256<<10)-total {
					return false
				}
				total += len(scalar.String)
			}
		} else {
			if value.List != nil || value.Scalar.Kind != value.Kind || !validSignupScalar(value.Scalar) || len(value.Scalar.String) > (256<<10)-total {
				return false
			}
			total += len(value.Scalar.String)
		}
	}
	return true
}

func validSignupScalar(s identity.AttributeScalar) bool {
	switch s.Kind {
	case identity.AttributeString:
		return len(s.String) <= 4096 && utf8.ValidString(s.String) && !s.Bool && s.Int64 == 0 && s.Time == (time.Time{})
	case identity.AttributeBool:
		return s.String == "" && s.Int64 == 0 && s.Time == (time.Time{})
	case identity.AttributeInt64:
		return s.String == "" && !s.Bool && s.Time == (time.Time{})
	case identity.AttributeTime:
		return s.String == "" && !s.Bool && s.Int64 == 0 && !s.Time.IsZero()
	default:
		return false
	}
}

// Format redacts the entire original request, including invalid input.
func (SignupRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SignupRequest(redacted)")
}

// LogValue denies implicit input projection into structured logs.
func (SignupRequest) LogValue() slog.Value {
	return slog.StringValue("password.SignupRequest(redacted)")
}

// MarshalJSON denies implicit export; the optional HTTP owner owns its schema.
func (SignupRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies text and map-key disclosure of original request input.
func (SignupRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
