package oauth

import (
	"fmt"
	"time"
)

// CallbackRateContext is nonsecret attribution resolved by the native RP owner
// from original state and browser custody. It is not admission, a reservation,
// provider proof or a renewable lease. Transport uses it only for the original
// tenant/provider/transaction rate bucket before its separate Callback call.
// Lifetime is the original configured interval, never remaining time or Now.
type CallbackRateContext struct {
	ProviderID, TransactionID string
	Lifetime                  time.Duration
}

// Format hides transaction correlation in diagnostics.
func (CallbackRateContext) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.CallbackRateContext(redacted)"))
}

// MarshalJSON refuses accidental export of private rate attribution.
func (CallbackRateContext) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit text export of private rate attribution.
func (CallbackRateContext) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
