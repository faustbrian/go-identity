package postgres

import (
	"encoding/base64"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// providerRefreshRequestKey lets the existing request-key owner allocate one
// random command per grant version. The adapter supplies the authenticated
// tenant/actor and exact refresh operation as the coordinator's key scope;
// HTTP callers never supply a key. Keep this encoding stable: changing it
// would let an uncertain provider send acquire a new command.
func providerRefreshRequestKey(account identity.AccountID, version uint64) (identity.IdempotencyKey, error) {
	if _, err := identity.ParseAccountID(string(account)); err != nil {
		return identity.IdempotencyKey{}, err
	}
	if version == 0 || version == math.MaxUint64 {
		return identity.IdempotencyKey{}, identity.InvalidInputError{Field: "token_version"}
	}

	// Base64url keeps case-sensitive imported IDs exact and keeps the delimiter
	// out of the encoding. A 128-byte ID and 20-digit version fit the key limit.
	key := base64.RawURLEncoding.AppendEncode([]byte("provider-refresh-v1."), []byte(account))
	key = strconv.AppendUint(append(key, '.'), version, 10)
	return identity.NewIdempotencyKey(key)
}
