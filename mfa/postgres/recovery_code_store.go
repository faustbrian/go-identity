package mfapostgres

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"maps"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// RecoveryVerificationKeys owns an immutable, bounded retained digest-key ring.
// It performs no IO and is safe for concurrent use. A missing stored key version
// fails closed; key rotation must retain versions while their sets remain active.
// Keys must be independent of intent, envelope and command-fingerprint keys.
type RecoveryVerificationKeys struct{ key func(uint32) ([32]byte, bool) }

// NewRecoveryVerificationKeys copies one to 64 nonzero versioned keys into opaque
// custody. Mutating the caller's map does not rotate retained sets. Zero denies.
func NewRecoveryVerificationKeys(keys map[uint32][32]byte) (RecoveryVerificationKeys, error) {
	if len(keys) < 1 || len(keys) > 64 {
		return RecoveryVerificationKeys{}, invalidAuthority()
	}
	for version, key := range keys {
		if version == 0 || key == ([32]byte{}) {
			return RecoveryVerificationKeys{}, invalidAuthority()
		}
	}
	owned := maps.Clone(keys)
	return RecoveryVerificationKeys{key: func(version uint32) ([32]byte, bool) { key, ok := owned[version]; return key, ok }}, nil
}

// Format prevents diagnostics from disclosing cryptographic custody.
func (RecoveryVerificationKeys) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.RecoveryVerificationKeys(redacted)"))
}

// MarshalJSON rejects key export.
func (RecoveryVerificationKeys) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects key export.
func (RecoveryVerificationKeys) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// RecoverySetMetadata is non-secret original set/version correlation, not proof
// that any code is valid or unused. Epoch is immutable across consumption and
// changes when regeneration creates a replacement set. RowVersion fences state.
type RecoverySetMetadata struct {
	TenantID                identity.TenantID
	UserID                  identity.UserID
	FactorID, SetID         string
	SetVersion, RowVersion  uint64
	FactorEnrollmentVersion uint64
	KeyVersion, CodeCount   uint32
}

type recoveryCodeRow struct {
	set      RecoverySetMetadata
	index    uint32
	digest   [32]byte
	consumed bool
}

// Keep this encoding identical to the original enrollment profile. Regeneration
// changes set identity/epoch, not the interpretation of existing stored digests.
func recoveryCodeBinding(m RecoverySetMetadata) ([]byte, error) {
	if m.SetVersion == 0 {
		return nil, invalidAuthority()
	}
	for _, id := range []string{string(m.TenantID), string(m.UserID)} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return nil, invalidAuthority()
		}
	}
	for _, id := range []string{m.FactorID, m.SetID} {
		if _, err := identity.ParseCommandID(id); err != nil {
			return nil, invalidAuthority()
		}
	}
	return json.Marshal(struct {
		Profile, Tenant, User, Factor, Set string
		Epoch                              uint64
	}{"mfa-recovery-code-v1", string(m.TenantID), string(m.UserID), m.FactorID, m.SetID, m.SetVersion})
}

func compareRecoveryCodes(ctx context.Context, keys RecoveryVerificationKeys, code auth.RecoveryCode, rows []recoveryCodeRow) (int, bool, error) {
	if ctx == nil || keys.key == nil || len(rows) > 4096 {
		return 0, false, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	matched, count := 0, 0
	var previous RecoverySetMetadata
	var digest [32]byte
	defer clear(digest[:])
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		if i == 0 || row.set != previous {
			key, ok := keys.key(row.set.KeyVersion)
			if !ok {
				return 0, false, identity.UnavailableError{}
			}
			binding, err := recoveryCodeBinding(row.set)
			if err == nil {
				digest, err = code.KeyedDigest(key, binding)
			}
			clear(key[:])
			clear(binding)
			if err != nil {
				return 0, false, invalidAuthority()
			}
			previous = row.set
		}
		// Compare every stored digest, including consumed rows. No matching
		// position short-circuits the bounded scan or skips a later retired key.
		equal := hmac.Equal(digest[:], row.digest[:])
		if equal && !row.consumed {
			matched, count = i, count+1
		}
	}
	if count > 1 {
		return 0, false, identity.UnavailableError{}
	}
	return matched, count == 1, nil
}
