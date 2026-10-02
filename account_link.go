package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"
)

// AccountLinkMode is a closed policy path, never a role or authority grant.
type AccountLinkMode uint8

const (
	AccountLinkExplicit AccountLinkMode = iota + 1
	AccountLinkImplicit
	AccountLinkAdministrative
)

// AccountLinkChange is exact, bounded intent. Account.Version must be one more
// than ExpectedAccountVersion, which is zero only for a never-used record ID.
// Nonzero history is retained after unlink; relinking requires fresh evidence
// and the current tombstone fence, not a stale callback or import assertion.
// Method optionally attaches an owner-validated provider credential; nil is a
// data-only link and must not change credential authority. Do not mutate input
// during calls. A change is neither a provider proof nor authorization.
//
// Implicit linking requires all three identifier fences and an exact canonical
// value independently established from a fresh verified provider claim under
// registered provider semantics. Other modes must omit those fields. An
// administrative reason is a registered policy token, not free-form evidence.
type AccountLinkChange struct {
	Mode                               AccountLinkMode
	Account                            Account
	Method                             *LoginMethod
	Reason                             PolicyReason
	ExpectedUserVersion                uint64
	ExpectedAccountVersion             uint64
	ExpectedSocialLinkVersion          uint64
	ExpectedCredentialVersion          uint64
	MatchedIdentifier                  IdentifierID
	VerifiedCanonicalIdentifier        string
	ExpectedIdentifierAuthorityVersion uint64
	ExpectedIdentifierVersion          uint64
	ExpectedVerificationVersion        uint64
}

// Format excludes provider and identifier values from diagnostics.
func (AccountLinkChange) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.AccountLinkChange(redacted)")
}

func (c AccountLinkChange) valid() bool {
	if c.Mode < AccountLinkExplicit || c.Mode > AccountLinkAdministrative || c.Account.Validate(c.Account.TenantID, c.Account.UserID) != nil || !unlinkVersion(c.ExpectedUserVersion) || c.ExpectedAccountVersion == ^uint64(0) || c.Account.Version != c.ExpectedAccountVersion+1 || !unlinkVersion(c.ExpectedSocialLinkVersion) || !unlinkVersion(c.ExpectedCredentialVersion) {
		return false
	}
	if c.Mode == AccountLinkAdministrative {
		if !validDirectoryID(string(c.Reason)) {
			return false
		}
	} else if c.Reason != "" {
		return false
	}
	if c.Mode == AccountLinkImplicit {
		if !validDirectoryID(string(c.MatchedIdentifier)) || !validIdentifierText(c.VerifiedCanonicalIdentifier) || !unlinkVersion(c.ExpectedIdentifierAuthorityVersion) || !unlinkVersion(c.ExpectedIdentifierVersion) || !unlinkVersion(c.ExpectedVerificationVersion) {
			return false
		}
	} else if c.MatchedIdentifier != "" || c.VerifiedCanonicalIdentifier != "" || c.ExpectedIdentifierAuthorityVersion != 0 || c.ExpectedIdentifierVersion != 0 || c.ExpectedVerificationVersion != 0 {
		return false
	}
	if c.Method != nil {
		m := c.Method
		if m.Credential.Validate(c.Account.TenantID, c.Account.UserID) != nil || m.Credential.Kind != CredentialProvider || m.AccountID != c.Account.ID || !validLinkExpiry(m.ExpiresAt) {
			return false
		}
	}
	return true
}

func cloneLinkChange(c AccountLinkChange) AccountLinkChange {
	if c.Method != nil {
		m := *c.Method
		c.Method = &m
	}
	return c
}

// AccountLinkState is one exact consistent primary lookup, not a client claim.
// Candidate binds absence/collision observations to the requested exact record
// and tenant/provider/issuer/subject key. SubjectOwner is nil only for proven
// absence under that key; a foreign owner's safe metadata may be retained
// internally but never disclosed. RecordVersion retains the candidate ID's
// tombstone history. SocialLinkVersion is the exact candidate connection scope;
// CredentialVersion is the tenant/user credential authority dimension.
// Identifiers is mandatory for implicit linking and shares the exact user
// aggregate with Access. Snapshots are immutable during a call.
type AccountLinkState struct {
	Access            AccountAccessSnapshot
	Candidate         Account
	RecordVersion     uint64
	SocialLinkVersion uint64
	CredentialVersion uint64
	SubjectOwner      *Account
	Identifiers       *IdentifierState
}

// Format redacts collision and primary eligibility observations.
func (AccountLinkState) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.AccountLinkState(redacted)")
}

// AccountLinkMutation is copied proposed next state, never a durable receipt.
// AddsCredential advances credential authority once, including a currently
// unusable provider credential. Data-only links preserve that dimension.
type AccountLinkMutation struct {
	Access            AccountAccessSnapshot
	Account           Account
	SocialLinkVersion uint64
	CredentialVersion uint64
	AddsCredential    bool
}

// Format redacts the proposed linked account and credential state.
func (AccountLinkMutation) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.AccountLinkMutation(redacted)")
}

func validLinkExpiry(t time.Time) bool {
	return t.IsZero() || t.UTC().Year() >= 1 && t.UTC().Year() <= 9999 && t.Nanosecond()%1000 == 0
}

func (s AccountLinkState) valid(c AccountLinkChange, now time.Time) bool {
	if now.IsZero() || now.UTC().Year() < 1 || now.UTC().Year() > 9999 || s.Candidate != c.Account || !(AccountSnapshot{User: s.Access.User, Accounts: s.Access.Accounts}).valid(c.Account.TenantID, c.Account.UserID) || s.SocialLinkVersion == 0 || s.CredentialVersion == 0 || len(s.Access.Methods) > 128 {
		return false
	}
	if s.SubjectOwner != nil {
		a := *s.SubjectOwner
		if a.Validate(c.Account.TenantID, a.UserID) != nil || a.Provider != c.Account.Provider || a.Issuer != c.Account.Issuer || a.Subject != c.Account.Subject {
			return false
		}
	}
	for j, m := range s.Access.Methods {
		if m.Credential.Validate(c.Account.TenantID, c.Account.UserID) != nil || !validLinkExpiry(m.ExpiresAt) {
			return false
		}
		for _, p := range s.Access.Methods[:j] {
			if p.Credential.ID == m.Credential.ID {
				return false
			}
		}
		if m.Credential.Kind == CredentialProvider {
			if !slices.ContainsFunc(s.Access.Accounts, func(a Account) bool { return a.ID == m.AccountID }) {
				return false
			}
		} else if m.AccountID != "" {
			return false
		}
	}
	if s.Identifiers != nil && (s.Identifiers.User != s.Access.User || s.Identifiers.validate(c.Account.TenantID, c.Account.UserID, now) != nil) {
		return false
	}
	return c.Mode != AccountLinkImplicit || s.Identifiers != nil
}

// ApplyAccountLink computes the identity-owned pure next state. It never
// transfers or merges an already-owned provider subject, including same-user
// duplicate links. Implicit linking requires a current verified email record
// and all exact authority/record/verification fences; email matching alone
// does not establish provider evidence. Existing access methods are conserved.
// Inputs are not mutated and errors return no partial state.
//
// The platform durable owner checks exact same-command replay first, then locks
// tenant provider-subject uniqueness (including absent keys), record/tombstone,
// current primary eligibility/identifiers and all authority dimensions. It must
// revalidate configured provider proof, current policy, fresh actor session or
// pre-auth binding, and consume applicable proof/risk with state, audit/events,
// token-vault participant and original receipt atomically. Canonical provider
// registration and provider ceremonies belong to their feature owners. This
// function neither authorizes nor proves those durable/cryptographic effects.
func ApplyAccountLink(s AccountLinkState, c AccountLinkChange, now time.Time) (AccountLinkMutation, error) {
	zero := AccountLinkMutation{}
	if !c.valid() || !s.valid(c, now) {
		return zero, InvalidInputError{Field: "account_link_state"}
	}
	if !s.Access.User.Status.AllowsAuthentication() {
		return zero, ForbiddenError{}
	}
	if s.Access.User.Version != c.ExpectedUserVersion || s.RecordVersion != c.ExpectedAccountVersion || s.SocialLinkVersion != c.ExpectedSocialLinkVersion || s.CredentialVersion != c.ExpectedCredentialVersion {
		return zero, ConflictError{}
	}
	if s.SubjectOwner != nil || len(s.Access.Accounts) == 100 || slices.ContainsFunc(s.Access.Accounts, func(a Account) bool {
		return a.ID == c.Account.ID || a.Provider == c.Account.Provider && a.Issuer == c.Account.Issuer && a.Subject == c.Account.Subject
	}) {
		return zero, ConflictError{}
	}
	if c.Mode == AccountLinkImplicit {
		is := s.Identifiers
		index := slices.IndexFunc(is.Identifiers, func(i Identifier) bool { return i.ID == c.MatchedIdentifier })
		if is.AuthorityVersion != c.ExpectedIdentifierAuthorityVersion || index < 0 {
			return zero, ConflictError{}
		}
		i, v := is.Identifiers[index], is.Verifications[index]
		if i.Version != c.ExpectedIdentifierVersion || v.Version != c.ExpectedVerificationVersion || i.Kind != IdentifierEmail || !i.Verified || v.State != VerificationVerified || i.CanonicalValue != c.VerifiedCanonicalIdentifier {
			return zero, ConflictError{}
		}
	}
	if c.Method != nil {
		if len(s.Access.Methods) == 128 || c.Method.Usable && !c.Method.ExpiresAt.IsZero() && !now.Before(c.Method.ExpiresAt) || slices.ContainsFunc(s.Access.Methods, func(m LoginMethod) bool { return m.Credential.ID == c.Method.Credential.ID }) {
			return zero, ConflictError{}
		}
	}
	next := AccountAccessSnapshot{User: s.Access.User, Accounts: slices.Clone(s.Access.Accounts), Methods: slices.Clone(s.Access.Methods)}
	next.User.Version++
	position := 0
	for position < len(next.Accounts) && next.Accounts[position].ID < c.Account.ID {
		position++
	}
	next.Accounts = slices.Insert(next.Accounts, position, c.Account)
	credentialVersion := s.CredentialVersion
	if c.Method != nil {
		next.Methods = append(next.Methods, *c.Method)
		credentialVersion++
	}
	return AccountLinkMutation{Access: next, Account: c.Account, SocialLinkVersion: s.SocialLinkVersion + 1, CredentialVersion: credentialVersion, AddsCredential: c.Method != nil}, nil
}

// AccountLinkIntentDigest is SHA-256 over the domain identity-account-link-v1
// followed by 23 length-prefixed UTF-8 fields in the order implemented below.
// It is an unkeyed signed-intent binding, NOT authority, a bearer, password hash
// or reuse tombstone. Exact mode, metadata, fences, credential and identifier
// choices are bound. Canonical provider policy must run before signing. No
// secrets are retained; invalid inputs return a zero digest and redacted error.
func AccountLinkIntentDigest(c AccountLinkChange) ([32]byte, error) {
	if !c.valid() {
		return [32]byte{}, InvalidInputError{Field: "link_intent"}
	}
	fields := []string{strconv.Itoa(int(c.Mode)), string(c.Account.ID), string(c.Account.TenantID), string(c.Account.UserID), c.Account.Provider, c.Account.Issuer, c.Account.Subject, strconv.FormatUint(c.Account.Version, 10), string(c.Reason), strconv.FormatUint(c.ExpectedUserVersion, 10), strconv.FormatUint(c.ExpectedAccountVersion, 10), strconv.FormatUint(c.ExpectedSocialLinkVersion, 10), strconv.FormatUint(c.ExpectedCredentialVersion, 10), string(c.MatchedIdentifier), c.VerifiedCanonicalIdentifier, strconv.FormatUint(c.ExpectedIdentifierAuthorityVersion, 10), strconv.FormatUint(c.ExpectedIdentifierVersion, 10), strconv.FormatUint(c.ExpectedVerificationVersion, 10), "absent", "", "", "", ""}
	if c.Method != nil {
		m := c.Method
		fields[18] = "present"
		fields[19] = string(m.Credential.ID)
		fields[20] = m.Credential.Owner
		fields[21] = strconv.FormatUint(m.Credential.Version, 10)
		fields[22] = strconv.FormatBool(m.Usable) + ":" + m.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "identity-account-link-v1\x00")
	var size [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(f)))
		_, _ = h.Write(size[:])
		_, _ = io.WriteString(h, f)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
