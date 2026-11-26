package onetap

import (
	"fmt"
	"net/netip"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// BrowserStartRequestSpec is the trusted transport's input to an anonymous
// One Tap start. Resolve the Remember choice once with the deployment's
// session policy. Network and Device come from trusted transport admission,
// not browser JSON or provider claims. Native execution selects the actor,
// provider, client and flow; none are caller input here. This explicit
// projection exposes its named fields to the caller; do not log it.
type BrowserStartRequestSpec struct {
	TenantID identity.TenantID
	Origin   string
	Network  string
	Device   string
	Key      identity.IdempotencyKey
	Options  BrowserStartOptions
	Remember session.RememberPolicy
}

// BrowserStartRequest retains the exact bounded browser intent. It is safe for
// concurrent reads. The zero value is invalid. Construction establishes no
// origin authorization, risk decision, keyed reservation or browser proof.
type BrowserStartRequest struct {
	// fmt can skip Format when traversing a caller's unexported field.
	// Keep the original behind a closure, as for identity.IdempotencyKey.
	original func() BrowserStartRequestSpec
}

// NewBrowserStartRequest freezes one selected prompt or popup button and an
// explicitly resolved Remember policy. It performs no IO or entropy work.
func NewBrowserStartRequest(spec BrowserStartRequestSpec) (BrowserStartRequest, error) {
	if _, err := identity.ParseIdentifierID(string(spec.TenantID)); err != nil {
		return BrowserStartRequest{}, failure(InvalidInput, nil)
	}
	if !canonicalOrigin(spec.Origin) || !browserStartNetwork(spec.Network) || !visible(spec.Device, 128) {
		return BrowserStartRequest{}, failure(InvalidInput, nil)
	}
	if spec.Key == (identity.IdempotencyKey{}) || spec.Options.prompt.valid == spec.Options.button.valid {
		return BrowserStartRequest{}, failure(InvalidInput, nil)
	}
	if _, err := spec.Remember.Bindings(); err != nil {
		return BrowserStartRequest{}, failure(InvalidInput, nil)
	}
	return BrowserStartRequest{original: func() BrowserStartRequestSpec { return spec }}, nil
}

func browserStartNetwork(text string) bool {
	if len(text) > 45 {
		return false
	}
	address, err := netip.ParseAddr(text)
	if err != nil || address.Zone() != "" || address.String() != text {
		return false
	}
	// The transport must unmap an IPv4 peer before setting the network risk
	// dimension; accepting both spellings could split the same peer's quota.
	return !address.Is4In6() && !address.IsUnspecified() && !address.IsMulticast()
}

// Bindings returns the original request to native execution without changing
// the opaque retry key, browser options or resolved lifetime. The zero value
// returns an empty spec and InvalidInput.
func (r BrowserStartRequest) Bindings() (BrowserStartRequestSpec, error) {
	if r.original == nil {
		return BrowserStartRequestSpec{}, failure(InvalidInput, nil)
	}
	return r.original(), nil
}

// Format redacts the original browser and retry context.
func (BrowserStartRequestSpec) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental export of transport context.
func (BrowserStartRequestSpec) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental export of transport context.
func (BrowserStartRequestSpec) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts the validated browser and retry context.
func (BrowserStartRequest) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental export of the validated original.
func (BrowserStartRequest) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental export of the validated original.
func (BrowserStartRequest) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
