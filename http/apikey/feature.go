// Package apikeyhttp composes explicitly selected strict-bearer API-key
// management routes. Native owners retain authentication, authorization,
// protected risk, durable transitions, original replay and reveal-once custody.
package apikeyhttp

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// Creator is the native original-key issuance port. Implementations must own
// current self/tenant/policy/factor authority and atomic protected effects.
// Calls must honor context and support concurrent independent requests.
type Creator interface {
	Create(context.Context, apikey.CreateRequest) (apikey.IssuanceResult, error)
}

// OrganizationCreator owns native current-member authorization independently
// of organization credential ownership. It preserves original keyed custody
// and atomic effects; calls honor context and support independent concurrency.
type OrganizationCreator interface {
	CreateOrganization(context.Context, apikey.OrganizationCreateRequest) (apikey.IssuanceResult, error)
}

// Rotator owns zero-overlap native successor issuance and original-key recovery.
// It must preserve grants and absolute expiry and never reconstruct plaintext.
// Calls must honor context and support concurrent independent requests.
type Rotator interface {
	Rotate(context.Context, apikey.Rotation) (apikey.IssuanceResult, error)
}

// Revoker owns native terminal revocation and original-key outcome recovery.
// It must commit required effects atomically and never infer success from absence.
// Calls must honor context and support concurrent independent requests.
type Revoker interface {
	Revoke(context.Context, apikey.Revocation) (identity.CommandResult, error)
}

// MetadataGetter owns current human/tenant/owner/configuration authorization for
// one copied stored record. It must honor ctx and support concurrent calls;
// reads neither verify nor debit a key and return no secret or digest.
type MetadataGetter interface {
	Get(context.Context, apikey.GetRequest) (apikey.GetResult, error)
}

// MetadataLister owns current authorization on every bounded live-view page.
// A cursor is only a position. Calls honor ctx and concurrency, never mutate
// key state, and return no partial page when authority is unavailable.
type MetadataLister interface {
	List(context.Context, apikey.ListRequest) (apikey.ListResult, error)
}

// Config borrows concurrency-safe owners for the lifetime of selected handlers.
// Supply only the native ports selected by FeatureConfig. Sessions supplies
// current transport subject custody for shared rate admission, not a substitute
// for the native final authority fences. No domain-store callback is accepted.
// Mutation ports must enforce the selected owner profile before effects: use
// native NewService for user-only management, not an organization-capable port.
// OrganizationOwned selects wire support, not a substitute authorization check.
// Network is copied; mutation body/decoded limits permit the native maximum
// grant. Mutations borrow SecretRate; metadata borrows the shared SafeRate
// owner, including its emergency budget, never a new per-route copy.
// Now is trusted, prompt and concurrency-safe. MaximumDuration is 1ms..30s;
// earlier inbound deadlines win. Construction performs no owner or network IO.
type Config struct {
	Network             identityhttp.NetworkConfig
	Sessions            *session.SessionService
	Creator             Creator
	OrganizationCreator OrganizationCreator
	Rotator             Rotator
	Revoker             Revoker
	// Updater is required only with Update; it owns current fresh authority,
	// non-expansion, exact CAS and original keyed outcome custody without secrets.
	Updater         apikey.Updater
	Getter          MetadataGetter
	Lister          MetadataLister
	SafeRate        *identityhttp.SafeRateLimiter
	SecretRate      *identityhttp.KeyedSecretRateLimiter
	Now             func() time.Time
	MaximumDuration time.Duration
}

// FeatureConfig selects each management route independently. Zero exposes
// nothing and is invalid; do not construct a feature when all flags are false.
// Revoke selects canonical POST /v1/apikey/delete, not a new protocol path.
// This profile accepts genuine password bearer sessions and unlimited uncached
// Narrow keys. Organization ownership requires explicit selection below.
// Update selects name/permission replacement without credential/expiry edits.
// Get/List return stored metadata across native-selected profiles, not current
// verification authority. This selects no recovery route, cookie fallback,
// legacy import, finite quota or API-key session login.
type FeatureConfig struct {
	Config
	Create, Rotate, Revoke bool
	Update                 bool
	Get, List              bool
	// OrganizationOwned explicitly selects organization management. Its creation
	// port is required only with Create; selected mutation ports must retain the
	// native organization authority, never a user-owner fallback.
	OrganizationOwned bool
}

// NewFeature validates and freezes a complete selected contribution without IO.
// Invalid dependencies return no partial feature. All selected mutations require
// the single original Idempotency-Key; no key or command is generated by HTTP.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	if c.OrganizationOwned && c.Create && missing(c.OrganizationCreator) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	mutations, reads := c.Create || c.Rotate || c.Revoke || c.Update, c.Get || c.List
	if !mutations && !reads || !c.Sessions.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if mutations && (!c.SecretRate.Configured() || c.Network.Limits.MaximumBodyBytes < 65536 || c.Network.Limits.MaximumDecodedBytes < 16384 || c.Network.Limits.MaximumFields < 72 || (c.Create || c.Update) && c.Network.Limits.MaximumDepth < 2) || reads && (!c.SafeRate.Configured() || c.Get && missing(c.Getter) || c.List && missing(c.Lister)) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	var ops []identityhttp.OperationDescriptor
	for _, selected := range []struct {
		action string
		on     bool
		owner  any
	}{{"create", c.Create, c.Creator}, {"rotate", c.Rotate, c.Rotator}, {"delete", c.Revoke, c.Revoker}, {"update", c.Update, c.Updater}} {
		if !selected.on {
			continue
		}
		if missing(selected.owner) {
			return identityhttp.Feature{}, identityhttp.ErrInvalidInput
		}
		h, err := newHandler(c.Config, selected.action, network, decoder, c.OrganizationOwned)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/apikey", OperationID: "identity.apikey." + selected.action, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: maximumResponseBytes})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = operationWire(selected.action, len(ops) == 0, c.OrganizationOwned)
		ops = append(ops, op)
	}
	for _, selected := range []struct {
		action string
		on     bool
	}{{"get", c.Get}, {"list", c.List}} {
		if !selected.on {
			continue
		}
		h, err := newMetadataHandler(c.Config, selected.action, network, decoder, c.OrganizationOwned)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/apikey", OperationID: "identity.apikey." + selected.action, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: maximumMetadataResponseBytes})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = metadataWire(selected.action, len(ops) == 0, c.OrganizationOwned)
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/apikey", Operations: ops})
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func (Config) Format(s fmt.State, _ rune) { io.WriteString(s, "apikeyhttp.Config(redacted)") }
func (FeatureConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikeyhttp.FeatureConfig(redacted)")
}
