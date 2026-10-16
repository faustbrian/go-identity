package emailhttp

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// FeatureConfig selects explicit email operations in one canonical feature.
// Nil operations expose neither routes nor metadata. SignupConfirmation and
// ManagedConfirmation are alternative owners of the same verification route;
// selecting both denies rather than guessing provenance or retrying an owner.
// ChangeConfirmation is a distinct action and may be selected alongside either.
// Request selectors separately enable cookie-only add/resend or change. No
// AddressRemove independently selects protected safe self-removal. No selector
// enables OTP or automatic signin.
// Construction borrows service/limiter lifetimes and copies their configuration;
// callers must not mutate inputs concurrently with construction.
type FeatureConfig struct {
	SignupConfirmation *ConfirmationConfig
	// VerificationSignin is an alternative original-browser registration
	// profile of that same route. Other confirmation profiles remain cookie-free.
	VerificationSignin  *VerificationSigninConfig
	ManagedConfirmation *ManagedConfirmationConfig
	// ProfiledConfirmation explicitly selects authenticated dispatch of both
	// profiles. It is mutually exclusive with either single-profile selection.
	ProfiledConfirmation *ProfiledConfirmationConfig
	ChangeConfirmation   *ChangeConfirmationConfig
	AddressGet           *AddressQueryConfig
	AddressList          *AddressQueryConfig
	VerificationRequest  *RequestConfig
	ChangeRequest        *RequestConfig
	AddressRemove        *RemovalConfig
}

// NewFeature contributes the actual selected handlers in one identity/email
// feature, avoiding duplicate feature identities across canonical operations.
// Empty selection and ambiguous verification ownership fail without IO.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware applies hooks to each selected protected operation.
// No hook can replace immutable request custody or choose an unselected owner.
func NewFeatureWithMiddleware(c FeatureConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	selections := 0
	if c.SignupConfirmation != nil {
		selections++
	}
	if c.VerificationSignin != nil {
		selections++
	}
	if c.ManagedConfirmation != nil {
		selections++
	}
	if c.ProfiledConfirmation != nil {
		selections++
	}
	if selections > 1 || selections == 0 && c.ChangeConfirmation == nil && c.AddressGet == nil && c.AddressList == nil && c.VerificationRequest == nil && c.ChangeRequest == nil && c.AddressRemove == nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	ops := make([]identityhttp.OperationDescriptor, 0, 2)
	if c.VerificationSignin != nil {
		h, err := newVerificationSigninHandler(*c.VerificationSignin, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := newEmailConfirmationOperation(h, "identity.email.verification-confirm", "Explicit original-browser registration confirmation then separately committed email-possession signin.")
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = verificationSigninWire()
		ops = append(ops, op)
	}
	if c.AddressRemove != nil {
		h, err := newAddressRemoveHandler(*c.AddressRemove, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: "identity.email.address-remove", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = removalWire(*c.AddressRemove)
		ops = append(ops, op)
	}
	for _, selected := range []struct {
		config *RequestConfig
		change bool
	}{{c.VerificationRequest, false}, {c.ChangeRequest, true}} {
		if selected.config == nil {
			continue
		}
		h, err := newRequestHandler(*selected.config, m, selected.change)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		action := "identity.email.verification-send"
		if selected.change {
			action = "identity.email.change-request"
		}
		csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: action, Handler: h, CSRF: csrf, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = requestWire(*selected.config, selected.change)
		ops = append(ops, op)
	}
	for _, selected := range []struct {
		config *AddressQueryConfig
		get    bool
	}{{c.AddressGet, true}, {c.AddressList, false}} {
		if selected.config == nil {
			continue
		}
		h, err := newAddressQueryHandler(*selected.config, m, selected.get)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		action := "identity.email.address-list"
		if selected.get {
			action = "identity.email.address-get"
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: action, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: maximumAddressResponse})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = addressQueryWire(*selected.config, selected.get)
		ops = append(ops, op)
	}
	if c.ProfiledConfirmation != nil {
		p := *c.ProfiledConfirmation
		if nilService(p.Service) {
			return identityhttp.Feature{}, identityhttp.ErrInvalidInput
		}
		t := ConfirmationConfig{Network: p.Network, Rate: p.Rate, Origin: p.Origin, ActorID: p.ActorID, PolicyRevision: p.PolicyRevision, Now: p.Now, MaximumDuration: p.MaximumDuration}
		h, err := newConfirmationHandler(t, m, p.Service, p.Service.VerificationRateSource)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := newEmailConfirmationOperation(h, "identity.email.verification-confirm", "Authenticated original signup or managed-address profile; no failed-owner fallback, session issuance or automatic signin.")
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.SignupConfirmation != nil {
		h, err := NewConfirmationHandlerWithMiddleware(*c.SignupConfirmation, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := newEmailConfirmationOperation(h, "identity.email.verification-confirm", "Original-signup require-before-signin no-session profile.")
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.ManagedConfirmation != nil {
		h, err := NewManagedConfirmationHandlerWithMiddleware(*c.ManagedConfirmation, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := newEmailConfirmationOperation(h, "identity.email.verification-confirm", "Original managed-address verification; distinct from signup and primary change, without session issuance.")
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.ChangeConfirmation != nil {
		h, err := NewChangeConfirmationHandlerWithMiddleware(*c.ChangeConfirmation, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := newEmailConfirmationOperation(h, "identity.email.change-confirm", "New-address-confirmed primary change with original fresh password authority, old-address notice and required session invalidation; no automatic signin.")
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/email", Operations: ops})
}

// Format redacts borrowed runtime composition.
func (FeatureConfig) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "emailhttp.FeatureConfig(redacted)")
}

// LogValue emits a constant marker.
func (FeatureConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.FeatureConfig(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (FeatureConfig) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit text export.
func (FeatureConfig) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
