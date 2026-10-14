package mfa

import (
	"crypto/hmac"
	"time"

	auth "github.com/faustbrian/go-authentication"
)

// totpOpaqueMatchingStep never extracts the submitted code. The trusted native
// factor owner supplies an independent comparison key and canonical scope with
// its retained key version, not a key derived from the factor secret. Only
// authentication's existing domain-separated digest contract is used. A matched
// counter still requires atomic replay advancement and continuation consumption.
func totpOpaqueMatchingStep(secret []byte, algorithm string, digits uint32, period time.Duration, skew uint32, now time.Time, lastStep uint64, hasLastStep bool, submitted auth.OneTimeCode, key [32]byte, binding []byte) (uint64, bool) {
	digest, err := submitted.KeyedDigest(key, binding)
	if err != nil {
		return 0, false
	}
	defer clear(digest[:])
	return totpMatchingStep(secret, algorithm, digits, period, skew, now, lastStep, hasLastStep, func(candidate []byte) bool {
		code, err := auth.NewOneTimeCode(string(candidate))
		if err != nil {
			return false
		}
		candidateDigest, err := code.KeyedDigest(key, binding)
		defer clear(candidateDigest[:])
		return err == nil && hmac.Equal(candidateDigest[:], digest[:])
	})
}
