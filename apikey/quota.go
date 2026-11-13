package apikey

import "time"

// TokenBucketPolicy defines continuously accrued tokens, capped at Capacity.
// RefillInterval is microsecond-exact because PostgreSQL owns quota time.
// A new key begins full. Policy is immutable within a configuration revision.
type TokenBucketPolicy struct {
	Capacity       uint64
	RefillAmount   uint64
	RefillInterval time.Duration
}

// Validate enforces the reference capacity ceiling and native time precision.
// Positive uint64 refill amounts are exact: native numeric arithmetic, not a
// duration multiplication or floating-point balance, owns fractional accrual.
func (p TokenBucketPolicy) Validate() error {
	if p.Capacity == 0 || p.Capacity > 1_000_000 || p.RefillAmount == 0 || p.RefillInterval <= 0 || p.RefillInterval%time.Microsecond != 0 {
		return ErrInvalid
	}
	return nil
}

// QuotaMetadata is a historical observation from the original verification
// transaction. Replaying it neither refills quota nor renews principal authority.
// Remaining counts whole tokens after the attempted debit; fractional credit is
// retained privately by the native owner. No credential or permission is granted.
type QuotaMetadata struct {
	TokenBucketPolicy
	Remaining  uint64
	ObservedAt time.Time
}

// Validate checks safe metadata shape only, never current allowance or authority.
func (m QuotaMetadata) Validate() error {
	if m.TokenBucketPolicy.Validate() != nil || m.Remaining > m.Capacity || m.ObservedAt.IsZero() || m.ObservedAt.Year() < 1 || m.ObservedAt.Year() > 9999 || m.ObservedAt != m.ObservedAt.UTC().Truncate(time.Microsecond) {
		return ErrInvalid
	}
	return nil
}
