package postgres

import (
	"errors"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProviderRefreshKeyConvergesOnOneAccountAndVersion(t *testing.T) {
	lookupAuthority := [32]byte{1}
	digest := func(account identity.AccountID, version uint64) [32]byte {
		t.Helper()
		key, err := providerRefreshRequestKey(account, version)
		if err != nil {
			t.Fatal("valid refresh target could not be correlated", err)
		}
		value, err := key.Digest(lookupAuthority)
		if err != nil {
			t.Fatal("refresh correlation did not use the request-key owner", err)
		}
		return value
	}

	original := digest("social.account-1", 59)
	if original == ([32]byte{}) || original != digest("social.account-1", 59) {
		t.Fatal("independent attempts would allocate separate commands for the same grant")
	}
	if original == digest("social.account-1", 60) ||
		original == digest("social.account-15", 9) ||
		original == digest("Social.account-1", 59) {
		t.Fatal("an account or version change reused the original grant command")
	}
	_ = digest(identity.AccountID(strings.Repeat("a", 128)), math.MaxUint64-1)
}

func TestProviderRefreshKeyRejectsTargetsThatCannotAdvance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account identity.AccountID
		version uint64
	}{
		{"empty-account", "", 1},
		{"noncanonical-account", " account-1", 1},
		{"overlong-account", identity.AccountID(strings.Repeat("a", 129)), 1},
		{"zero-version", "account-1", 0},
		{"overflow", "account-1", math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := providerRefreshRequestKey(tc.account, tc.version)
			var invalid identity.InvalidInputError
			if key != (identity.IdempotencyKey{}) || !errors.As(err, &invalid) {
				t.Fatal("invalid grant target was made eligible for request-key custody", err)
			}
		})
	}
}
