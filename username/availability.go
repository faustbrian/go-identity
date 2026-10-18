package username

import (
	"context"
	"fmt"
	"io"
)

// AvailabilityRequest borrows a candidate and trusted tenant/network scope.
// Network must come from the server's trusted proxy policy, never a body field.
// Native execution validates names with the selected enrollment policy and
// charges its bounded durable rate profile. Each independent call is an attempt;
// callers cannot supply a reusable counter ID to avoid rate accounting.
type AvailabilityRequest struct{ TenantID, Username, Network string }

// AvailabilityResult is an advisory observation, never a reservation, promise
// of subsequent signup/rename success, account-status disclosure or permission.
// A false result does not identify an owner or distinguish a live name from
// cooldown history. Errors carry no candidate, identifier or provider details.
type AvailabilityResult struct{ Available bool }

// AvailabilityService owns bounded, rate-limited canonical discovery. Callers
// supply trusted scope and configuration, not an application uniqueness store.
// Calls accept cancellation, are concurrent-safe with independent immutable
// inputs and retain no request resources. Atomic mutation must recheck ownership.
type AvailabilityService interface {
	Available(context.Context, AvailabilityRequest) (AvailabilityResult, error)
}

// Format redacts candidate and trusted correlation data for every verb.
func (AvailabilityRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "username.AvailabilityRequest(redacted)")
}

// MarshalJSON refuses implicit export of sensitive discovery input.
func (AvailabilityRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// MarshalText refuses implicit text/map-key export of sensitive discovery input.
func (AvailabilityRequest) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
