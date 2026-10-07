package identity

import (
	"encoding/base64"
	"strings"

	authentication "github.com/faustbrian/go-authentication"
)

// NewFeatureOneTimeCodePreAuthCommand freezes an OTP submission and its separate
// original pre-auth cookie in opaque command custody, never in scalar metadata.
// Cookie is the canonical unpadded base64url transport of 32..64 bytes. This
// validates syntax only: the native session/OTP owner must independently derive
// the named cookie commitment from the original flow, admit primary state and
// current policy, and consume atomically. Neither a cookie nor code is proof.
//
// Existing one-time-code constructors remain unchanged. Invalid spec, zero code
// or malformed cookie returns zero Command and redacted InvalidInputError. No IO,
// callbacks, time samples or disclosure occur. Immutable copies are concurrency
// safe; discard every secret-bearing copy at terminal outcomes. Recovery uses
// code/cookie-free metadata; Go cannot guarantee immutable secret erasure.
func NewFeatureOneTimeCodePreAuthCommand(spec FeatureCommandSpec, code authentication.OneTimeCode, cookie authentication.BearerCredential) (Command, error) {
	wire := cookie.Token()
	if len(wire) < 43 || len(wire) > 86 {
		return Command{}, invalidFeatureCommand()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
	defer clear(raw)
	if err != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeatureOneTimeCodeCommand(spec, code)
	if err != nil {
		return Command{}, err
	}
	frozen := authentication.NewBearerCredential(strings.Clone(wire))
	c.feature.preAuthCookie = &frozen
	return c, nil
}

// PreAuthCookie lends the exact submitted bearer only to trusted native owners
// for independently derived flow-cookie comparison. It never returns a caller
// digest or grants authentication/one-use authority. Zero, ordinary, code-only
// and mixed commands return zero/false. Feature projections contain neither
// bearer nor code, and cannot reconstruct them. Discard borrowed copies after
// use; never log, serialize, persist or disclose Token. No IO or callbacks run.
func (c Command) PreAuthCookie() (authentication.BearerCredential, bool) {
	if c.feature == nil || c.feature.preAuthCookie == nil || c.feature.code == nil {
		return authentication.BearerCredential{}, false
	}
	if _, ok := c.Feature(); !ok {
		return authentication.BearerCredential{}, false
	}
	return *c.feature.preAuthCookie, true
}
