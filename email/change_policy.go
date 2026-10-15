package email

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CurrentAddressPolicy selects the original notification address. Zero denies;
// caller ordering or the candidate mailbox never chooses the old address.
type CurrentAddressPolicy uint8

const (
	// RequirePrimaryAddress requires an existing verified primary email.
	RequirePrimaryAddress CurrentAddressPolicy = iota + 1
	// PrimaryOrSoleVerifiedAddress additionally allows initial-primary
	// establishment when exactly one pre-existing verified email exists.
	PrimaryOrSoleVerifiedAddress
)

// ChangeSessionPolicy is the selected atomic session effect. Zero is invalid.
type ChangeSessionPolicy uint8

const (
	// InvalidateIdentifierSessions advances identifier authority with the
	// primary switch. Existing sessions carrying the old authority must deny;
	// confirmation issues no replacement session or authentication cookie.
	InvalidateIdentifierSessions ChangeSessionPolicy = iota + 1
)

// ChangeProfile is immutable startup policy for new-address-confirmed changes
// with old-address notification. It grants no authority and owns no resources.
type ChangeProfile struct {
	CurrentAddress CurrentAddressPolicy
	Sessions       ChangeSessionPolicy
}

// Validate rejects unselected or unknown policy rather than inferring defaults.
func (p ChangeProfile) Validate() error {
	if (p.CurrentAddress != RequirePrimaryAddress && p.CurrentAddress != PrimaryOrSoleVerifiedAddress) || p.Sessions != InvalidateIdentifierSessions {
		return ErrInvalidVerification
	}
	return nil
}

// PreviousAddress retains exact original-address predecessors, independently
// versioned verification and whether this is replacement or establishment.
// CanonicalAddress is private delivery intent, not proof or current authority.
type PreviousAddress struct {
	ID                                     identity.IdentifierID
	CanonicalAddress                       string
	IdentifierVersion, VerificationVersion uint64
	Primary                                bool
}

// SelectPrevious chooses from a complete primary partition without changing it.
// The candidate is excluded. Invalid/inconsistent or ambiguous partitions deny.
// Native request and confirmation must repeat selection under their transaction
// lock and bind the exact result to original encrypted and signed intent.
func (p ChangeProfile) SelectPrevious(s identity.IdentifierState, candidate identity.IdentifierID, now time.Time) (PreviousAddress, error) {
	if _, err := identity.ParseIdentifierID(string(candidate)); err != nil {
		return PreviousAddress{}, ErrInvalidVerification
	}
	if p.Validate() != nil || s.User.Version == math.MaxUint64 || s.User.Status != identity.StatusActive || s.AuthorityVersion == math.MaxUint64 || len(s.Identifiers) == 0 {
		return PreviousAddress{}, ErrInvalidVerification
	}
	// The kernel owns complete partition consistency, including canonical
	// collisions. Do not create a weaker second validator in email selection.
	if _, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{
		TenantID: s.User.TenantID, UserID: s.User.ID, IdentifierID: s.Identifiers[0].ID,
		State: s, ObservedAt: now, Values: identity.IdentifierValuesOmitted,
	}); err != nil {
		return PreviousAddress{}, ErrInvalidVerification
	}
	var primary, sole PreviousAddress
	verified := 0
	for n, a := range s.Identifiers {
		v := s.Verifications[n]
		if a.Version == math.MaxUint64 || v.Version == math.MaxUint64 {
			return PreviousAddress{}, ErrInvalidVerification
		}
		if a.Kind != identity.IdentifierEmail || a.ID == candidate || !a.Verified {
			continue
		}
		old := PreviousAddress{ID: a.ID, CanonicalAddress: a.CanonicalValue, IdentifierVersion: a.Version, VerificationVersion: v.Version, Primary: a.Primary}
		verified++
		sole = old
		if a.Primary {
			primary = old
		}
	}
	if primary.ID != "" {
		return primary, nil
	}
	if p.CurrentAddress == PrimaryOrSoleVerifiedAddress && verified == 1 {
		return sole, nil
	}
	return PreviousAddress{}, ErrInvalidVerification
}

// Format omits the notification mailbox and correlated record metadata.
func (PreviousAddress) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.PreviousAddress(redacted)")
}

// MarshalJSON rejects implicit sensitive delivery-intent export.
func (PreviousAddress) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit sensitive delivery-intent export.
func (PreviousAddress) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostic output.
func (PreviousAddress) LogValue() slog.Value {
	return slog.StringValue("email.PreviousAddress(redacted)")
}
