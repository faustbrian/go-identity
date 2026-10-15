package identity

import (
	"encoding/base64"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v2"
)

// NewFeatureOneTimeCodeSessionCommand freezes an OTP submission with a separate
// original session token in opaque custody, never in scalar metadata. Token must
// be canonical unpadded base64url of 32..64 bytes. It cannot create pre-auth
// cookie custody. This is syntax validation, not possession proof, authenticated
// provenance, active status or permission; native session admission must derive
// the lookup digest under the original retained key and compare primary owners.
// Invalid scope, zero code or malformed token returns a zero Command and redacted
// InvalidInputError. Construction is bounded and performs no IO or callbacks.
// Copies are immutable and safe for concurrent reads. Never retain, persist,
// export or log borrowed secrets beyond bounded use. Recovery uses code/token-free
// metadata; Go cannot guarantee complete immutable secret erasure.
func NewFeatureOneTimeCodeSessionCommand(spec FeatureCommandSpec, code authentication.OneTimeCode, token authentication.BearerCredential) (Command, error) {
	// Root cannot import its session module, which already depends on root.
	// This validates transport syntax only; session retains digest/admission policy.
	wire := token.Token()
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
	c.feature.sessionToken = &frozen
	return c, nil
}

// SessionToken lends the exact submitted session bearer to trusted native
// owners for code-free issuance or code-bearing submissions without fabricating
// the other. It returns zero/false for zero, ordinary, code-only, pre-auth or mixed
// commands. A scalar projection cannot reconstruct this custody. Possession,
// current activity and authorization must be checked independently; this method
// grants none. Discard borrowed copies after bounded use, never log, persist or
// serialize Token. No code or bearer enters Feature projections or recovery.
func (c Command) SessionToken() (authentication.BearerCredential, bool) {
	if c.feature == nil || c.feature.sessionToken == nil {
		return authentication.BearerCredential{}, false
	}
	if _, ok := c.Feature(); !ok {
		return authentication.BearerCredential{}, false
	}
	return *c.feature.sessionToken, true
}
