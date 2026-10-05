package identity

import (
	"fmt"
	"io"
	"time"
)

// IdentifierLoginMethod is one authority-owner-evaluated human login path.
// Method.Usable includes current credential, policy, factor and provider checks;
// a caller boolean is not authority. An optional identifier dependency names its
// exact current record and verification versions. Empty IdentifierID denotes an
// independent path and requires zero versions and false requirements. Different
// identifiers may provide alternative paths for the same exact credential.
// RequiresPrimary/RequiresVerified come from the selected login policy, never
// client input. Replacement never inherits access to the old canonical value.
type IdentifierLoginMethod struct {
	Method                                 LoginMethod
	IdentifierID                           IdentifierID
	IdentifierVersion, VerificationVersion uint64
	RequiresVerified, RequiresPrimary      bool
}

// IdentifierAccessSnapshot is a complete consistent primary view for the pure
// final-access decision. Methods contains at most 128 distinct login paths;
// Accounts has AccountSnapshot semantics. The durable owner must establish
// current method eligibility and lock every applicable owner before constructing
// this view. It is neither an authority proof nor a reusable validity lease.
// Treat all input collections as immutable during a call.
type IdentifierAccessSnapshot struct {
	State    IdentifierState
	Accounts []Account
	Methods  []IdentifierLoginMethod
}

// Format prevents identifiers, account subjects and credential linkage leaking.
func (IdentifierAccessSnapshot) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.IdentifierAccessSnapshot(redacted)")
}

// Format redacts login-path linkage and eligibility observations.
func (IdentifierLoginMethod) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.IdentifierLoginMethod(redacted)")
}

// IdentifierAccessPlan is a copied provisional mutation and bounded count of
// surviving usable human login paths, not distinct credentials. It grants no
// permission or durable outcome. A successful decision never consumes proof.
type IdentifierAccessPlan struct {
	Mutation             IdentifierMutation
	RemainingUsablePaths uint16
}

// Format redacts the provisional mutation and enumeration-sensitive count.
func (IdentifierAccessPlan) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.IdentifierAccessPlan(redacted)")
}

// CheckIdentifierAccess computes the identifier transition and rejects any
// resulting loss of all human login paths. Call only after authorization, and
// repeat under durable owner locks with current credential/factor/provider
// eligibility and one trusted clock sample. Independent methods survive;
// identifier-bound methods need the same canonical value and required successor
// verification/primary state. Expiry is exclusive; API keys never count.
// Malformed/foreign/duplicate paths return InvalidInput, stale dependency
// versions return Conflict, and no surviving path returns FinalAccessError.
// Other transition errors retain ApplyIdentifierChange semantics. All errors
// return a zero plan; inputs are not mutated. No IO or authority refresh occurs.
// Pre-auth registration must use its distinct workflow, not this current-human
// access decision before a login method exists.
func CheckIdentifierAccess(snapshot IdentifierAccessSnapshot, change IdentifierChange, now time.Time) (IdentifierAccessPlan, error) {
	zero := IdentifierAccessPlan{}
	invalid := InvalidInputError{Field: "identifier_access"}
	if len(snapshot.Methods) > 128 || !(AccountSnapshot{User: snapshot.State.User, Accounts: snapshot.Accounts}).valid(change.TenantID, change.UserID) {
		return zero, invalid
	}
	mutation, err := ApplyIdentifierChange(snapshot.State, change, now)
	if err != nil {
		return zero, err
	}
	var surviving uint16
	for index, path := range snapshot.Methods {
		method := path.Method
		if method.Credential.Validate(change.TenantID, change.UserID) != nil || !validAccessExpiry(method.ExpiresAt) {
			return zero, invalid
		}
		if method.Credential.Kind == CredentialProvider {
			found := false
			for _, account := range snapshot.Accounts {
				if account.ID == method.AccountID {
					found = true
					break
				}
			}
			if !found {
				return zero, invalid
			}
		} else if method.AccountID != "" {
			return zero, invalid
		}
		for _, previous := range snapshot.Methods[:index] {
			if previous.Method.Credential.ID == method.Credential.ID &&
				(previous.Method.Credential != method.Credential || previous.Method.AccountID != method.AccountID || previous.IdentifierID == path.IdentifierID) {
				return zero, invalid
			}
		}
		eligible := method.Credential.Kind != CredentialAPIKey && method.Usable && (method.ExpiresAt.IsZero() || now.Before(method.ExpiresAt))
		if path.IdentifierID == "" {
			if path.IdentifierVersion != 0 || path.VerificationVersion != 0 || path.RequiresPrimary || path.RequiresVerified {
				return zero, invalid
			}
		} else {
			if path.IdentifierVersion == 0 || path.VerificationVersion == 0 {
				return zero, invalid
			}
			oldIndex := -1
			for i, identifier := range snapshot.State.Identifiers {
				if identifier.ID == path.IdentifierID {
					oldIndex = i
					break
				}
			}
			if oldIndex == -1 {
				return zero, invalid
			}
			old := snapshot.State.Identifiers[oldIndex]
			if old.Version != path.IdentifierVersion || snapshot.State.Verifications[oldIndex].Version != path.VerificationVersion {
				return zero, ConflictError{}
			}
			retained := false
			for _, next := range mutation.State.Identifiers {
				if next.ID == old.ID && next.Kind == old.Kind && next.CanonicalValue == old.CanonicalValue && (!path.RequiresVerified || next.Verified) && (!path.RequiresPrimary || next.Primary) {
					retained = true
					break
				}
			}
			eligible = eligible && retained
		}
		if eligible {
			surviving++
		}
	}
	if surviving == 0 {
		return zero, FinalAccessError{}
	}
	return IdentifierAccessPlan{Mutation: mutation, RemainingUsablePaths: surviving}, nil
}

func validAccessExpiry(at time.Time) bool {
	return at.IsZero() || at.UTC().Year() >= 1 && at.UTC().Year() <= 9999 && at.Nanosecond()%1000 == 0
}
