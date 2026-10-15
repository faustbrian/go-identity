package identity

import (
	"encoding/base64"
	"strings"

	"github.com/faustbrian/go-authentication/v2"
)

// NewFeaturePreAuthCommand freezes a feature command with only its submitted
// original pre-auth cookie, not an OTP submission. Cookie must be canonical
// unpadded base64url of 32..64 bytes. Construction validates syntax and scope,
// not possession, active flow, current authority or permission. The native
// owner must independently derive the original cookie commitment and check
// primary state before mutation; a cookie must never imply authentication.
// Invalid input returns zero Command and redacted InvalidInputError. No IO,
// clocks or callbacks run. Immutable copies support concurrent reads; discard
// secret-bearing copies after bounded use. Recovery uses secret-free metadata.
func NewFeaturePreAuthCommand(spec FeatureCommandSpec, cookie authentication.BearerCredential) (Command, error) {
	return newFeatureBearerCommand(spec, cookie, false)
}

// NewFeatureSessionCommand freezes a feature command with only its submitted
// original session token, not an OTP or authenticated proof. Token has the same
// bounded canonical transport as NewFeaturePreAuthCommand but remains a disjoint
// custody variant even when bytes match. The native session owner must derive
// the lookup digest under the original retained key and recheck current primary
// ownership, freshness and authority. Syntax alone confers none of these.
// Invalid input returns zero Command and redacted InvalidInputError. It performs
// no IO or callbacks. Immutable copies support concurrent reads; never persist,
// log or serialize borrowed bearer copies. Go cannot guarantee their erasure.
func NewFeatureSessionCommand(spec FeatureCommandSpec, token authentication.BearerCredential) (Command, error) {
	return newFeatureBearerCommand(spec, token, true)
}

func newFeatureBearerCommand(spec FeatureCommandSpec, bearer authentication.BearerCredential, session bool) (Command, error) {
	wire := bearer.Token()
	if len(wire) < 43 || len(wire) > 86 {
		return Command{}, invalidFeatureCommand()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
	defer clear(raw)
	if err != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
		return Command{}, invalidFeatureCommand()
	}
	command, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	frozen := authentication.NewBearerCredential(strings.Clone(wire))
	if session {
		command.feature.sessionToken = &frozen
	} else {
		command.feature.preAuthCookie = &frozen
	}
	return command, nil
}
