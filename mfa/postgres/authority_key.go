package mfapostgres

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	identity "github.com/faustbrian/go-identity"
)

// FactorAuthorityKey derives the version-one account-factor scope key from
// exact canonical tenant/user IDs, without normalization or IO. It is lookup
// metadata, not authentication or a current generation. The key is "factor:v1:"
// plus unpadded base64url SHA-256 of "golib.identity.mfa.authority.v1\x00" and
// each ID framed by its big-endian uint16 UTF-8 byte length. This owned stable
// profile distinguishes tenant/user framing and never aliases a session or
// credential dimension. Invalid input returns zero and a redacted error.
func FactorAuthorityKey(tenant identity.TenantID, user identity.UserID) (string, error) {
	for _, id := range []string{string(tenant), string(user)} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return "", invalidAuthority()
		}
	}
	h := sha256.New()
	_, _ = h.Write([]byte("golib.identity.mfa.authority.v1\x00"))
	for _, id := range []string{string(tenant), string(user)} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(id)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(id))
	}
	return "factor:v1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
