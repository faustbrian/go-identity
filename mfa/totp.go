package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// totpCode implements RFC 6238's HOTP moving-factor mechanics through standard
// library HMAC. This private primitive grants no enrollment, verification or
// replay authority. Its caller owns decrypted secret lifetime, absolute time
// and skew policy, shared attempt accounting and atomic last-step advancement.
// The returned code is transient secret material: clear it after comparison,
// never return it from a verification operation or put it in diagnostics.
func totpCode(secret []byte, algorithm string, digits uint32, step uint64) ([]byte, bool) {
	if len(secret) < 20 || len(secret) > 128 || digits < 6 || digits > 10 {
		return nil, false
	}
	var hashFn func() hash.Hash
	switch algorithm {
	case "SHA1":
		// SHA1 is used only in RFC 4226's HMAC profile, not for signatures.
		hashFn = sha1.New
	case "SHA256":
		hashFn = sha256.New
	case "SHA512":
		hashFn = sha512.New
	default:
		return nil, false
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(hashFn, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 15
	value := uint64(binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff)
	modulus := uint64(1)
	for range digits {
		modulus *= 10
	}
	value %= modulus
	code := make([]byte, digits)
	for i := len(code) - 1; i >= 0; i-- {
		code[i] = byte(value%10) + '0'
		value /= 10
	}
	return code, true
}
