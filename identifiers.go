package identity

import (
	"fmt"
	"io"
	"slices"
	"time"
	"unicode/utf8"
)

// IdentifierID is an exact case-sensitive record ID, separate from an email,
// phone, username or provider subject. Empty is invalid; at most 128 UTF-8
// bytes are accepted. Imported canonical IDs are preserved unchanged.
type IdentifierID string

// ParseIdentifierID validates structure without granting ownership or authority.
func ParseIdentifierID(raw string) (IdentifierID, error) {
	if !validDirectoryID(raw) {
		return "", InvalidInputError{Field: "identifier_id"}
	}
	return IdentifierID(raw), nil
}

// Identifier is an identity-owned directory record. Tenant scope is inherited
// from its enclosing authoritative User partition, never inferred from UserID.
// Values must already be canonical under the selected versioned feature policy;
// structural validation does not normalize or prove uniqueness/verification.
// Primary is per kind and requires verification. Treat snapshots as immutable.
type Identifier struct {
	ID             IdentifierID
	UserID         UserID
	Kind           IdentifierKind
	CanonicalValue string
	DisplayValue   string
	Verified       bool
	Primary        bool
	Version        uint64
}

// Validate checks the exact user, closed kind, bounded values and positive
// record version. It confers no authority and does not accept a claimed primary
// without verification. Canonical/display text is at most 512 UTF-8 bytes with
// no C0/C1 controls; provider-subject spaces are preserved, not trimmed.
func (i Identifier) Validate(user UserID) error {
	if !validDirectoryID(string(i.ID)) || !validDirectoryID(string(user)) || i.UserID != user || !i.Kind.Valid() || !validIdentifierText(i.CanonicalValue) || i.DisplayValue != "" && !validIdentifierText(i.DisplayValue) || i.Version == 0 || i.Primary && !i.Verified {
		return InvalidInputError{Field: "identifier"}
	}
	return nil
}

// Valid recognizes a persisted identifier kind. Empty is only an omitted list
// filter, never a valid kind for an identifier record or mutation.
func (k IdentifierKind) Valid() bool {
	return k == IdentifierEmail || k == IdentifierPhone || k == IdentifierUsername || k == IdentifierProviderSubject
}

func validIdentifierText(value string) bool {
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return false
		}
	}
	return true
}

// Format prevents canonical and display identifiers from entering diagnostics.
func (Identifier) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.Identifier(redacted)")
}

// VerificationState is closed persisted verification state, not a challenge or
// bearer. Pending requires a fresh feature-owned challenge; revoked is denied.
type VerificationState uint8

const (
	VerificationPending VerificationState = iota + 1
	VerificationVerified
	VerificationRevoked
)

// Verification records the identity-owned verification state of an exact
// IdentifierID. Version is independent of the identifier record's version;
// primary selection does not mint verification or reset its original time.
// VerifiedAt is absent for pending and may retain a historical time for revoked.
type Verification struct {
	IdentifierID IdentifierID
	State        VerificationState
	VerifiedAt   time.Time
	Version      uint64
}

// Validate checks one identifier's consistent verification projection and one
// trusted current time. Persisted instants have microsecond precision; verified
// time is nonzero, no later than now and within years 1..9999. Nothing is fetched
// or consumed. In particular setting Verified does not prove a challenge.
func (v Verification) Validate(identifier Identifier, now time.Time) error {
	if now.IsZero() || now.UTC().Year() < 1 || now.UTC().Year() > 9999 || identifier.Validate(identifier.UserID) != nil || v.IdentifierID != identifier.ID || v.Version == 0 || v.State < VerificationPending || v.State > VerificationRevoked || identifier.Verified != (v.State == VerificationVerified) {
		return InvalidInputError{Field: "verification"}
	}
	if v.State == VerificationPending && !v.VerifiedAt.IsZero() || v.State == VerificationVerified && v.VerifiedAt.IsZero() {
		return InvalidInputError{Field: "verified_at"}
	}
	if !v.VerifiedAt.IsZero() && (v.VerifiedAt.UTC().Year() < 1 || v.VerifiedAt.UTC().Year() > 9999 || v.VerifiedAt.Nanosecond()%1000 != 0 || v.VerifiedAt.After(now)) {
		return InvalidInputError{Field: "verified_at"}
	}
	return nil
}

// Format redacts verification metadata in diagnostic output.
func (Verification) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.Verification(redacted)")
}

// IdentifierState is a complete, consistent primary tenant/user partition at
// the mutation lock boundary. Identifiers are strictly ID-ordered, at most 128;
// Verifications correspond positionally and exactly. AuthorityVersion is the
// tenant/user identifier dimension, not the user-authority dimension. All
// versions are positive. Do not mutate input collections during a call.
type IdentifierState struct {
	User             User
	Identifiers      []Identifier
	Verifications    []Verification
	AuthorityVersion uint64
}

// Format redacts the complete primary directory projection.
func (IdentifierState) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.IdentifierState(redacted)")
}

// IdentifierAction selects one pure domain transition, never authorization.
type IdentifierAction uint8

const (
	IdentifierAttach IdentifierAction = iota + 1
	IdentifierVerify
	IdentifierMakePrimary
	IdentifierReplace
	IdentifierRemove
	// IdentifierRestartVerification advances only an existing pending,
	// non-primary verification generation. Native resend must authorize fresh
	// proof and atomically replace delivery/capability custody; generic identifier
	// commands do not expose this feature-specific transition.
	IdentifierRestartVerification
	// IdentifierVerifyPrimary verifies one pending email and selects it as
	// primary in one native transition. The feature owner must prove original
	// new-address possession and current change policy; generic identifier
	// commands do not expose this compound action.
	IdentifierVerifyPrimary
)

// IdentifierChange is bounded intent and exact optimistic fences. Attach and
// Replace supply Kind/CanonicalValue/DisplayValue; other actions must omit
// them. Attach must omit target versions; other actions require both exact
// target versions. Replacement preserves ID/kind, resets verification and
// primary, and retires the old value. It cannot edit display-only metadata.
// Trusted feature owners establish canonicalization, proof and reuse policy;
// client input must never directly reach ApplyIdentifierChange.
type IdentifierChange struct {
	TenantID                    TenantID
	UserID                      UserID
	Action                      IdentifierAction
	ID                          IdentifierID
	Kind                        IdentifierKind
	CanonicalValue              string
	DisplayValue                string
	ExpectedUserVersion         uint64
	ExpectedAuthorityVersion    uint64
	ExpectedIdentifierVersion   uint64
	ExpectedVerificationVersion uint64
}

// Format redacts candidate canonical/display values.
func (IdentifierChange) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.IdentifierChange(redacted)")
}

// IdentifierMutation is privately copied proposed state, not a committed
// outcome. Retired and RetiredVerification are present only for replacement
// or removal. Removal advances their versions and revokes verification;
// replacement retains the original pair for old-value reuse tombstone creation.
// The adapter must derive a scoped keyed non-reversible reuse digest, never
// persist canonical values in plaintext tombstones/events/audit. Legal storage
// of current directory values remains a separate encrypted storage policy.
type IdentifierMutation struct {
	State               IdentifierState
	Retired             *Identifier
	RetiredVerification *Verification
}

// Format redacts proposed state and retired identifier values.
func (IdentifierMutation) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.IdentifierMutation(redacted)")
}

// ApplyIdentifierChange computes an all-or-nothing copied next state without
// I/O, goroutines, locks, proof verification, clock reads or input mutation.
// Active users only; overflow and stale versions deny. Each successful change
// advances user aggregate and identifier authority exactly once. Primary
// switching bumps both changed records without renewing verification time.
// Same-value replacement and repeated verify/primary are conflicts, not replay.
//
// The platform durable owner must check exact same-command replay first, lock
// the full partition and tenant uniqueness index, validate current operation
// authorization/canonical policy, establish proof/version/session freshness,
// enforce final usable access and old-value cooldown/reuse policy, then consume
// applicable one-use proof/risk and persist state, tombstones, lifecycle events,
// audit and original receipt atomically. This function proves none of those
// durable/authority claims. Verify is usable only after the feature's real
// subject/value/version-bound challenge succeeds; a caller boolean is not proof.
// Errors return zero mutation. now is one trusted owner sample; newly persisted
// verification time is UTC truncated to microseconds, never a new proof lifetime.
func ApplyIdentifierChange(state IdentifierState, change IdentifierChange, now time.Time) (IdentifierMutation, error) {
	zero := IdentifierMutation{}
	if !validDirectoryID(string(change.TenantID)) || !validDirectoryID(string(change.UserID)) || !validDirectoryID(string(change.ID)) || change.Action < IdentifierAttach || change.Action > IdentifierVerifyPrimary || !unlinkVersion(change.ExpectedUserVersion) || !unlinkVersion(change.ExpectedAuthorityVersion) || state.validate(change.TenantID, change.UserID, now) != nil {
		return zero, InvalidInputError{Field: "identifier_change"}
	}
	if !state.User.Status.AllowsAuthentication() {
		return zero, ForbiddenError{}
	}
	if state.User.Version != change.ExpectedUserVersion || state.AuthorityVersion != change.ExpectedAuthorityVersion {
		return zero, ConflictError{}
	}
	candidate := change.Action == IdentifierAttach || change.Action == IdentifierReplace
	if candidate {
		if !change.Kind.Valid() || !validIdentifierText(change.CanonicalValue) || change.DisplayValue != "" && !validIdentifierText(change.DisplayValue) {
			return zero, InvalidInputError{Field: "identifier_value"}
		}
	} else if change.Kind != "" || change.CanonicalValue != "" || change.DisplayValue != "" {
		return zero, InvalidInputError{Field: "identifier_value"}
	}
	index := slices.IndexFunc(state.Identifiers, func(i Identifier) bool { return i.ID == change.ID })
	if change.Action == IdentifierAttach {
		if change.ExpectedIdentifierVersion != 0 || change.ExpectedVerificationVersion != 0 {
			return zero, InvalidInputError{Field: "identifier_version"}
		}
		if index >= 0 || len(state.Identifiers) == 128 {
			return zero, ConflictError{}
		}
	} else {
		if !unlinkVersion(change.ExpectedIdentifierVersion) || !unlinkVersion(change.ExpectedVerificationVersion) {
			return zero, InvalidInputError{Field: "identifier_version"}
		}
		if index < 0 || state.Identifiers[index].Version != change.ExpectedIdentifierVersion || state.Verifications[index].Version != change.ExpectedVerificationVersion {
			return zero, ConflictError{}
		}
		if change.Action == IdentifierReplace && state.Identifiers[index].Kind != change.Kind {
			return zero, InvalidInputError{Field: "identifier_kind"}
		}
	}
	if candidate {
		for _, i := range state.Identifiers {
			if i.Kind == change.Kind && i.CanonicalValue == change.CanonicalValue {
				return zero, ConflictError{}
			}
		}
	}
	next := IdentifierState{User: state.User, Identifiers: slices.Clone(state.Identifiers), Verifications: slices.Clone(state.Verifications), AuthorityVersion: state.AuthorityVersion + 1}
	next.User.Version++
	result := IdentifierMutation{State: next}
	switch change.Action {
	case IdentifierAttach:
		position := 0
		for position < len(next.Identifiers) && next.Identifiers[position].ID < change.ID {
			position++
		}
		result.State.Identifiers = slices.Insert(next.Identifiers, position, Identifier{ID: change.ID, UserID: change.UserID, Kind: change.Kind, CanonicalValue: change.CanonicalValue, DisplayValue: change.DisplayValue, Version: 1})
		result.State.Verifications = slices.Insert(next.Verifications, position, Verification{IdentifierID: change.ID, State: VerificationPending, Version: 1})
	case IdentifierRestartVerification:
		if next.Identifiers[index].Verified || next.Identifiers[index].Primary || next.Verifications[index].State != VerificationPending {
			return zero, ForbiddenError{}
		}
		result.State.Identifiers[index].Version++
		result.State.Verifications[index].Version++
	case IdentifierVerify, IdentifierVerifyPrimary:
		if next.Verifications[index].State != VerificationPending {
			return zero, ConflictError{}
		}
		if change.Action == IdentifierVerifyPrimary && next.Identifiers[index].Kind != IdentifierEmail {
			return zero, InvalidInputError{Field: "identifier_kind"}
		}
		result.State.Identifiers[index].Verified = true
		result.State.Identifiers[index].Version++
		result.State.Verifications[index].State = VerificationVerified
		result.State.Verifications[index].VerifiedAt = now.UTC().Truncate(time.Microsecond)
		result.State.Verifications[index].Version++
		if change.Action == IdentifierVerifyPrimary {
			if err := selectIdentifierPrimary(&result.State, index, false); err != nil {
				return zero, err
			}
		}
	case IdentifierMakePrimary:
		if !next.Identifiers[index].Verified || next.Identifiers[index].Primary {
			return zero, ConflictError{}
		}
		if err := selectIdentifierPrimary(&result.State, index, true); err != nil {
			return zero, err
		}
	case IdentifierReplace, IdentifierRemove:
		old, verification := next.Identifiers[index], next.Verifications[index]
		result.Retired, result.RetiredVerification = &old, &verification
		if change.Action == IdentifierRemove {
			result.Retired.Version++
			result.Retired.Primary, result.Retired.Verified = false, false
			result.RetiredVerification.State = VerificationRevoked
			result.RetiredVerification.Version++
			result.State.Identifiers = slices.Delete(next.Identifiers, index, index+1)
			result.State.Verifications = slices.Delete(next.Verifications, index, index+1)
		} else {
			result.State.Identifiers[index] = Identifier{ID: change.ID, UserID: change.UserID, Kind: change.Kind, CanonicalValue: change.CanonicalValue, DisplayValue: change.DisplayValue, Version: old.Version + 1}
			result.State.Verifications[index] = Verification{IdentifierID: change.ID, State: VerificationPending, Version: verification.Version + 1}
		}
	}
	return result, nil
}

func selectIdentifierPrimary(next *IdentifierState, index int, advanceTarget bool) error {
	for j, i := range next.Identifiers {
		if i.Kind == next.Identifiers[index].Kind && i.Primary {
			if !unlinkVersion(i.Version) {
				return ConflictError{}
			}
			next.Identifiers[j].Primary = false
			next.Identifiers[j].Version++
		}
	}
	next.Identifiers[index].Primary = true
	if advanceTarget {
		next.Identifiers[index].Version++
	}
	return nil
}

func (s IdentifierState) validate(tenant TenantID, user UserID, now time.Time) error {
	if s.User.Validate(tenant) != nil || s.User.ID != user || s.AuthorityVersion == 0 || len(s.Identifiers) > 128 || len(s.Verifications) != len(s.Identifiers) || now.UTC().Truncate(time.Microsecond).IsZero() || now.UTC().Year() < 1 || now.UTC().Year() > 9999 {
		return InvalidInputError{Field: "identifier_state"}
	}
	for j, i := range s.Identifiers {
		if i.Validate(user) != nil || s.Verifications[j].Validate(i, now) != nil || j > 0 && i.ID <= s.Identifiers[j-1].ID {
			return InvalidInputError{Field: "identifier_state"}
		}
		for _, previous := range s.Identifiers[:j] {
			if previous.Kind == i.Kind && (previous.CanonicalValue == i.CanonicalValue || previous.Primary && i.Primary) {
				return InvalidInputError{Field: "identifier_state"}
			}
		}
	}
	return nil
}
