package scimhttp

import (
	"context"
	"fmt"
	"net/http"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const managedUsersReplaceOperation = "identity.scim.user-replace"

// ManagedUsersReplaceExecutor owns current bearer authorization, complete User
// replacement, If-Match comparison, atomic mutation and replay. It calls admit
// once, synchronously, after current authority and request preflight but before
// command or write effects. It honors ctx, supports concurrent calls and does
// not retain the request, its body or its admission callback.
type ManagedUsersReplaceExecutor interface {
	ExecuteManagedAdmittedReplace(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedUsersReplaceConfig selects conditional managed User PUT. Network and
// Limits match the deployed router and native SCIM profile. Rate borrows the
// shared atomic backend, namespace and key. Owners must outlive requests.
// MaximumDuration is 1ms..30s and never extends an earlier deadline.
type ManagedUsersReplaceConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedUsersReplaceExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
}

// Format redacts borrowed credentials and configuration.
func (ManagedUsersReplaceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedUsersReplaceConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedUsersReplaceConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedUsersReplaceConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedUsersReplaceFeature opts in only to PUT /scim/v2/Users/{resource_id}.
// It forwards the issued bearer, original If-Match and bounded complete User
// body to native authority, then returns its exact User, ETag and Location only
// after one allowed admission. It accepts no query, trailer, caller retry key
// or cookie authority. The native owner defines replacement and replay; this
// construction performs no I/O and adds no cache or retry.
func NewManagedUsersReplaceFeature(c ManagedUsersReplaceConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newManagedUsersConditionalFeature(c.Network, c.Rate, c.Limits, c.MaximumDuration, http.MethodPut,
		scim.UserReplace, managedUsersReplaceOperation, c.Executor.ExecuteManagedAdmittedReplace, managedUsersReplaceWire)
}
