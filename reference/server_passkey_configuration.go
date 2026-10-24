package reference

import (
	"context"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPasskeyConfiguration independently selects cookie enrollment, signin,
// safe self inventory, label update and deletion. Nil selects no passkey routes or metadata. Native
// passkeys and session owners are required. Enrollment/signin also require the
// signed original browser-device profile; enrollment requires both native
// action primaries to select cookie transport. Signin/inventory require the explicit
// Session.Passkey common admission. Options require Passkey.KeyedOptions. Discoverable
// additionally requires Signin and native risk-policy opt-in; no fallback is
// attempted. Update requires explicit native Management with a cookie primary
// and actual signed proof reader, but no browser-device ceremony. Delete requires
// native Deletion with a cookie primary and its actual configured reset recovery
// owner. Signup is a separate explicit selection requiring native signup and
// original pre-auth/device custody. No conditional UI or MFA fallback is enabled.
//
// Inventory reuses an existing session/MFA/email safe limiter. Only when none
// exists must its three explicit inventory rate settings select that owner;
// supplying competing settings is rejected. Degraded must finish within ctx
// and support concurrent calls. Mutation rates borrow the shared HTTP auth and
// verification identities; no consumer store or alternative workflow is accepted.
type HTTPPasskeyConfiguration struct {
	Registration, Signin, Inventory, Discoverable bool
	// DiscoverableOnly explicitly rejects identifier-based signin and requires
	// Discoverable. It needs no email/password comparison configuration.
	DiscoverableOnly bool
	// Signup selects original-flow passkey-first registration and a distinct
	// passkey-signup initiation method. It requires native Passkey.Signup and
	// Session.Passkey; it never substitutes an enrollment proof or password.
	Signup                        bool
	Update, Delete                bool
	InventoryRateNamespace        string
	InventoryEmergencyMaximumKeys int
	InventoryDegraded             func(context.Context, identityhttp.SafeRateEvent) error
}

func (HTTPPasskeyConfiguration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.HTTPPasskeyConfiguration(redacted)"))
}

// MarshalJSON denies implicit deployment/callback export.
func (HTTPPasskeyConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit deployment/callback export.
func (HTTPPasskeyConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type passkeyHTTPState struct {
	config       HTTPPasskeyConfiguration
	verification *identityhttp.ChallengeVerificationRateLimiter
	secret       *identityhttp.KeyedSecretRateLimiter
	safe         *identityhttp.SafeRateLimiter
	ownedSafe    bool
	native       PasskeyConfiguration
	device       session.BrowserDeviceConfig
	now          func() time.Time
	address      email.AddressParser
	csrf         []session.CSRFKey
}

func (h *passkeyHTTPState) close() {
	if h == nil {
		return
	}
	if h.verification != nil {
		h.verification.Close()
	}
	if h.secret != nil {
		h.secret.Close()
	}
	if h.ownedSafe && h.safe != nil {
		h.safe.Close()
	}
}

func composePasskeyHTTP(c StoreConfiguration, owner *passkeyState, sessions *sessionState, proofs *passwordVerificationState, original *preAuthHTTPState, shared *httpRateState, existing *sessionHTTPState, mfa *mfaListHTTPState, addresses *emailAddressesHTTPState) (_ *passkeyHTTPState, err error) {
	if c.HTTPPasskey == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_passkey"}
	h := *c.HTTPPasskey
	if !h.Registration && !h.Signup && !h.Signin && !h.Inventory && !h.Update && !h.Delete || h.Discoverable && !h.Signin || h.DiscoverableOnly && !h.Discoverable || c.Passkey == nil || owner == nil || sessions == nil || sessions.reader == nil || c.Session == nil || (h.Signup || h.Signin || h.Inventory) && !c.Session.Passkey || c.Session.Native.Execution.Clock == nil || c.HTTPRate == nil || shared == nil {
		return nil, invalid
	}
	n := *c.Passkey
	// The HTTP owner supplies a cookie synchronizer to both enrollment phases.
	// A native bearer source deliberately rejects that custody, so do not
	// advertise a selected route that can never execute its protected operation.
	if h.Registration && (n.OptionsPrimary.Transport != session.CredentialCookie || n.RegistrationPrimary.Transport != session.CredentialCookie) {
		return nil, invalid
	}
	out := &passkeyHTTPState{config: h, native: n, now: c.Session.Native.Execution.Clock.Now, csrf: slices.Clone(c.Session.CSRFKeys)}
	defer func() {
		if err != nil {
			out.close()
		}
	}()
	if h.Registration || h.Signin || h.Signup {
		if n.KeyedOptions == nil || original == nil || original.device == nil || n.Flow.Origin != original.deployment.Origin || h.Registration && owner.enrollment == nil || h.Signin && owner.signin == nil || h.Signup && owner.signup == nil {
			return nil, invalid
		}
		out.device = *original.device
		// These are the same fixed rate.verify identities as password verification
		// when selected, so switching workflows does not mint another IP budget.
		namespace, key := c.HTTPRate.Namespace, c.HTTPRate.IdentifierKey
		if selected := c.HTTPPasswordVerification; selected != nil {
			namespace, key = selected.RateNamespace, selected.RateKey
		}
		out.verification, err = identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: shared.backend, Namespace: namespace, Key: key, Now: out.now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return nil, invalid
		}
	}
	if h.Signup {
		if n.Signup == nil || n.Signup.Flow.FlowTTL != 5*time.Minute || n.Signup.Flow.Origin != original.deployment.Origin || n.Signup.Flow.Cookie != original.deployment.Cookie || n.Signup.Flow.Action != "identity.passkey.register-verify" {
			return nil, invalid
		}
	}
	if h.Registration && (proofs == nil || proofs.proofs == nil || len(c.Session.CSRFKeys) == 0) {
		return nil, invalid
	}
	if h.Update {
		if n.Management == nil || owner.management == nil || n.Management.Primary.Transport != session.CredentialCookie || proofs == nil || proofs.proofs == nil || len(c.Session.CSRFKeys) == 0 {
			return nil, invalid
		}
	}
	if h.Delete && (n.Deletion == nil || owner.deletion == nil || n.Deletion.Primary.Transport != session.CredentialCookie || proofs == nil || proofs.proofs == nil || len(c.Session.CSRFKeys) == 0) {
		return nil, invalid
	}
	if h.Update || h.Delete {
		out.secret, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: out.now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return nil, invalid
		}
	}
	if h.Signin {
		if !h.DiscoverableOnly {
			if c.PasswordSignin == nil {
				return nil, invalid
			}
			out.address, err = email.NewAddressParser(c.PasswordSignin.Native.Address)
			if err != nil {
				return nil, invalid
			}
		}
		if n.Flow.FlowTTL != 5*time.Minute {
			return nil, invalid
		}
		flow, a := n.Flow.Cookie.DeletionAttributes()
		common, b := original.deployment.Cookie.DeletionAttributes()
		if a != nil || b != nil || flow.String() != common.String() {
			return nil, invalid
		}
	}
	if h.Inventory {
		if owner.inventory == nil {
			return nil, invalid
		}
		if existing != nil {
			out.safe = existing.rate
		} else if mfa != nil {
			out.safe = mfa.rate
		} else if addresses != nil {
			out.safe = addresses.rate
		}
		if out.safe != nil {
			if h.InventoryRateNamespace != "" || h.InventoryEmergencyMaximumKeys != 0 || h.InventoryDegraded != nil {
				return nil, invalid
			}
		} else {
			out.safe, err = identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: shared.backend, Namespace: h.InventoryRateNamespace, Now: out.now, Degraded: h.InventoryDegraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: h.InventoryEmergencyMaximumKeys})
			if err != nil {
				return nil, invalid
			}
			out.ownedSafe = true
		}
	} else if h.InventoryRateNamespace != "" || h.InventoryEmergencyMaximumKeys != 0 || h.InventoryDegraded != nil {
		return nil, invalid
	}
	return out, nil
}
