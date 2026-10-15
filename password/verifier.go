package password

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

// ErrCredentialAbsent is the owned repository's missing exact credential result.
// Public verification folds it into the same result as a password mismatch.
var ErrCredentialAbsent = errors.New("identity.password.credential_absent")

// CredentialKey selects one already canonicalized account in a trusted tenant.
// It does not parse email/phone/username or establish tenant lookup permission.
// SubjectID uses the kernel's existing UserID, not a second identity scalar.
type CredentialKey struct {
	TenantID  identity.TenantID
	SubjectID identity.UserID
}

// CredentialSnapshot joins owned password material and kernel authority in one
// consistent primary read. The reference version is also the material version:
// every material change must advance it. This is sensitive data, not a proof,
// lease, authentication result or permission to mutate credentials.
type CredentialSnapshot struct {
	// A closure keeps fmt's unsupported-verb fallback from traversing private
	// wrapper fields into a pointer's encoded-hash referent. It has no mutable
	// state, IO or global registry and returns an immutable observation copy.
	custody func() credentialSnapshot
}

type credentialSnapshot struct {
	Authority   identity.CredentialAuthorityRecord
	EncodedHash primitive.EncodedHash
}

// NewCredentialSnapshot copies a primary observation into immutable opaque
// custody. The adapter must supply a consistent, provenance-valid read;
// construction establishes neither provenance nor eligibility. Malformed scopes,
// zero versions and absent material deny; inactive accounts remain representable.
// Each material change must advance Authority.Credential.Version. Explicit
// EncodedHash access reveals sensitive verifier material and must never be logged.
func NewCredentialSnapshot(authority identity.CredentialAuthorityRecord, hash primitive.EncodedHash) (CredentialSnapshot, error) {
	ref := authority.Credential
	if authority.User.Validate(ref.TenantID) != nil || ref.Validate(ref.TenantID, authority.User.ID) != nil || ref.Kind != identity.CredentialPassword || ref.Owner != "identity/password" || authority.AuthorityVersion == 0 || hash.String() == "" {
		return CredentialSnapshot{}, ErrPasswordWork
	}
	retained := credentialSnapshot{Authority: authority, EncodedHash: hash}
	return CredentialSnapshot{custody: func() credentialSnapshot { return retained }}, nil
}

// Authority returns a copy of the original kernel projection. Zero returns zero.
// Mutating this projection cannot modify the retained credential observation.
func (s CredentialSnapshot) Authority() identity.CredentialAuthorityRecord {
	if s.custody == nil {
		return identity.CredentialAuthorityRecord{}
	}
	return s.custody().Authority
}

// EncodedHash exposes verifier material only for bounded owned comparison.
// Zero returns zero. Do not serialize or log this explicit projection.
func (s CredentialSnapshot) EncodedHash() primitive.EncodedHash {
	if s.custody == nil {
		return primitive.EncodedHash{}
	}
	return s.custody().EncodedHash
}

// Format redacts credential material and account metadata in direct diagnostics.
func (CredentialSnapshot) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.CredentialSnapshot(redacted)")
}

// MarshalJSON denies implicit credential snapshot serialization.
func (CredentialSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrPasswordWork }

// MarshalText denies implicit credential snapshot serialization.
func (CredentialSnapshot) MarshalText() ([]byte, error) { return nil, ErrPasswordWork }

// CredentialVerificationRepository is the concurrency-safe platform adapter
// port. Each read must join hash, exact reference, enabled/expiry, user status and
// user-wide credential epoch in one authoritative primary snapshot. No cached
// positive fallback or consumer-written storage implementation is supported.
// Missing accounts/passwords return ErrCredentialAbsent; unavailable or corrupt
// storage returns a redacted error. Reads honor the supplied bounded context.
// The repository owns IO resources and does not retain candidate secrets.
type CredentialVerificationRepository interface {
	ReadPasswordCredential(context.Context, CredentialKey) (CredentialSnapshot, error)
}

// VerifyPasswordRequest carries caller-owned ephemeral password custody and an
// already canonicalized account. Empty SubjectID selects unknown-identifier
// dummy work. ExpectedVersion zero omits the caller's version constraint.
// There is no request-selectable dummy hash or resource policy. Treat this input
// as immutable during verification; the caller must destroy Password afterward.
type VerifyPasswordRequest struct {
	TenantID        identity.TenantID
	SubjectID       identity.UserID
	Password        primitive.Secret
	ExpectedVersion uint64
}

// Format redacts the entire verification input.
func (VerifyPasswordRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.VerifyPasswordRequest(redacted)")
}

// MarshalJSON denies implicit verification-input serialization.
func (VerifyPasswordRequest) MarshalJSON() ([]byte, error) { return nil, ErrPasswordWork }

// MarshalText denies implicit verification-input serialization.
func (VerifyPasswordRequest) MarshalText() ([]byte, error) { return nil, ErrPasswordWork }

// PasswordVerification is a comparison result, not authorization or a bearer.
// Zero is the indistinguishable unknown/missing/blocked/mismatched result.
// A match carries the exact credential version and primitive upgrade advice;
// it issues no assurance, reauthentication proof or session. The protected
// workflow must recheck authority and perform any upgrade atomically with its
// risk/MFA/session effects. Copying this value cannot extend validity.
type PasswordVerification struct {
	Matched           bool
	NeedsRehash       bool
	CredentialVersion uint64
}

// PasswordVerifier performs bounded raw-byte comparison for canonical accounts.
// It deliberately excludes identifier lookup, risk/MFA, upgrades and issuance;
// all login methods must use the same owning signin workflow for those effects.
type PasswordVerifier interface {
	VerifyPassword(context.Context, VerifyPasswordRequest) (PasswordVerification, error)
}

// VerifierConfig freezes trusted composition. All fields are required. Now and
// Repository must be concurrency-safe. Timeout is in (0,10s]; MaximumBytes is
// in [1,1MiB] and within Primitive's limits. DummyHash must exactly match the
// selected current primitive policy, generated independently of user input.
// This layer supplies no deployment defaults, owns no goroutines/resources,
// and cannot be configured through an untrusted request.
type VerifierConfig struct {
	Primitive    *primitive.Service
	Repository   CredentialVerificationRepository
	MaximumBytes uint32
	Timeout      time.Duration
	DummyHash    primitive.EncodedHash
	Now          func() time.Time
}

// CredentialVerifier is immutable trusted composition, safe for concurrent calls
// when its configured dependencies honor their contracts. Its zero value denies.
type CredentialVerifier struct {
	work       passwordWork
	repository CredentialVerificationRepository
	now        func() time.Time
}

// NewPasswordVerifier validates explicit composition without reading storage,
// borrowing a password or performing provider/cryptographic work.
func NewPasswordVerifier(c VerifierConfig) (*CredentialVerifier, error) {
	w := passwordWork{primitive: c.Primitive, minimum: 1, maximum: c.MaximumBytes, timeout: c.Timeout, dummy: c.DummyHash}
	if !w.valid() || c.Timeout > 10*time.Second || c.Repository == nil || c.Now == nil {
		return nil, ErrPasswordWork
	}
	return &CredentialVerifier{work: w, repository: c.Repository, now: c.Now}, nil
}

// VerifyPassword compares exact secret bytes, using real current-policy dummy
// work for unknown/missing accounts. Existing short passwords remain verifiable.
// A candidate match is returned only after a second consistent primary read
// preserves its original reference, epoch, material and eligibility. Version,
// status, scope and expiry denial are neutral. Other dependency failures/panics
// are ErrPasswordWork; cancellation retains context errors. This is not a
// wall-clock constant-time guarantee across storage or legacy hash algorithms.
// No IO runs under Secret.Use and no match is persisted or consumed here.
func (v *CredentialVerifier) VerifyPassword(ctx context.Context, request VerifyPasswordRequest) (result PasswordVerification, err error) {
	defer func() {
		if recover() != nil {
			result = PasswordVerification{}
			err = ErrPasswordWork
		}
	}()
	if v == nil || ctx == nil || v.repository == nil || v.now == nil || !v.work.valid() {
		return result, ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, v.work.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	key := CredentialKey{TenantID: request.TenantID, SubjectID: request.SubjectID}
	user := key.SubjectID
	if user == "" {
		user = "unknown"
	}
	if (identity.CredentialAuthorityQuery{TenantID: key.TenantID, UserID: user, CredentialID: "password"}).Validate() != nil {
		return result, ErrPasswordWork
	}
	started := v.now()
	if !validVerificationTime(started) {
		return result, ErrPasswordWork
	}
	var original CredentialSnapshot
	known := false
	if key.SubjectID != "" {
		original, err = v.repository.ReadPasswordCredential(ctx, key)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil && !errors.Is(err, ErrCredentialAbsent) {
			return result, ErrPasswordWork
		}
		known = err == nil
	}
	comparison, err := v.work.verify(ctx, request.Password, original.EncodedHash(), known)
	if err != nil {
		return result, err
	}
	now := v.now()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !validVerificationTime(now) || now.Before(started) || now.Sub(started) > v.work.timeout {
		return result, ErrPasswordWork
	}
	originalAuthority := original.Authority()
	if !comparison.Match() || !known || !eligiblePasswordSnapshot(original, key, now) || (request.ExpectedVersion != 0 && request.ExpectedVersion != originalAuthority.Credential.Version) {
		return result, nil
	}
	current, err := v.repository.ReadPasswordCredential(ctx, key)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if errors.Is(err, ErrCredentialAbsent) {
		return result, nil
	}
	if err != nil {
		return result, ErrPasswordWork
	}
	final := v.now()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !validVerificationTime(final) || final.Before(now) || final.Sub(started) > v.work.timeout {
		return result, ErrPasswordWork
	}
	currentAuthority := current.Authority()
	if !eligiblePasswordSnapshot(original, key, final) || !eligiblePasswordSnapshot(current, key, final) || currentAuthority.Credential != originalAuthority.Credential || currentAuthority.AuthorityVersion != originalAuthority.AuthorityVersion || current.EncodedHash().String() != original.EncodedHash().String() {
		return result, nil
	}
	if request.Password.Len() == 0 {
		return result, ErrInvalidPassword
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return PasswordVerification{Matched: true, NeedsRehash: comparison.NeedsRehash(), CredentialVersion: originalAuthority.Credential.Version}, nil
}

func validVerificationTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

func eligiblePasswordSnapshot(s CredentialSnapshot, key CredentialKey, now time.Time) bool {
	authority := s.Authority()
	ref := authority.Credential
	return ref.TenantID == key.TenantID && ref.UserID == key.SubjectID && ref.Kind == identity.CredentialPassword && ref.Owner == "identity/password" && identity.CheckCredentialAuthority(authority, ref, authority.AuthorityVersion, now) == nil
}
