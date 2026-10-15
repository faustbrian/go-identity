package postgres

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// ManagedEmailPrevious is original encrypted change intent, not authority.
// The email owner chooses it; the kernel repeats these exact facts under the
// complete partition lock before attaching or promoting the candidate.
type ManagedEmailPrevious struct {
	ID                                     identity.IdentifierID
	CanonicalAddress                       string
	IdentifierVersion, VerificationVersion uint64
	Primary, AllowInitialPrimary           bool
}

func previousEmailFields(p ManagedEmailPrevious, candidate identity.IdentifierID, prefix string) ([]identity.FeatureField, error) {
	if p == (ManagedEmailPrevious{}) {
		return nil, nil
	}
	if _, err := identity.ParseIdentifierID(string(p.ID)); err != nil || p.ID == candidate || p.CanonicalAddress == "" || len(p.CanonicalAddress) > 254 || p.IdentifierVersion == 0 || p.IdentifierVersion == ^uint64(0) || p.VerificationVersion == 0 || p.VerificationVersion == ^uint64(0) || !p.Primary && !p.AllowInitialPrimary {
		return nil, invalidEmailVerification()
	}
	return []identity.FeatureField{
		{Name: prefix + "previous-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.ID)}},
		{Name: prefix + "previous-address", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.CanonicalAddress}},
		{Name: prefix + "previous-identifier-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.IdentifierVersion}},
		{Name: prefix + "previous-verification-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.VerificationVersion}},
		{Name: prefix + "previous-primary", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: p.Primary}},
		{Name: prefix + "allow-initial-primary", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: p.AllowInitialPrimary}},
	}, nil
}

func checkPreviousEmail(s identity.IdentifierState, p ManagedEmailPrevious, candidate identity.IdentifierID) error {
	if _, err := previousEmailFields(p, candidate, ""); err != nil || p == (ManagedEmailPrevious{}) {
		return identity.ForbiddenError{}
	}
	matched, verified, primaries := false, 0, 0
	for n, a := range s.Identifiers {
		if a.Kind != identity.IdentifierEmail || a.ID == candidate {
			continue
		}
		if a.Verified {
			verified++
		}
		if a.Primary {
			primaries++
		}
		if a.ID == p.ID {
			v := s.Verifications[n]
			matched = a.Verified && v.State == identity.VerificationVerified && a.Primary == p.Primary && a.CanonicalValue == p.CanonicalAddress && a.Version == p.IdentifierVersion && v.Version == p.VerificationVersion
		}
	}
	if !matched || p.Primary && primaries != 1 || !p.Primary && (!p.AllowInitialPrimary || primaries != 0 || verified != 1) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Format redacts notification intent and correlated predecessor metadata.
func (ManagedEmailPrevious) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ManagedEmailPrevious(redacted)"))
}

// MarshalJSON rejects implicit sensitive original-intent export.
func (ManagedEmailPrevious) MarshalJSON() ([]byte, error) { return nil, invalidEmailVerification() }
