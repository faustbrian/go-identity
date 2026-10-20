package identity

import (
	"strings"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	primitive "github.com/faustbrian/go-password/v2"
)

type phonePasswordResetCommandState struct {
	input               bool
	password            primitive.Secret
	hash                string
	proof               capability.Proof
	phoneCode, totpCode auth.OneTimeCode
	preAuthCookie       auth.BearerCredential
}

// NewFeaturePhonePasswordResetInputCommand freezes a joint original password,
// canonical reset proof, phone OTP and independent TOTP submission. Only the
// user-targeted identity/phone password-reset-complete.native-v1 descriptor is
// supported. This is structural custody, never proof of successful verification,
// carrier safety, risk admission or permission to consume any artifact.
//
// Password bounds are 1..1 MiB; proof transport is 32..4096 canonical bytes.
// Codes retain upstream opaque custody and structural bounds. No password or
// token bytes are copied, normalized, exposed, verified or consumed. Callers
// keep borrowed owners alive during bounded use and destroy the password after
// use. Copies share terminal password destruction and proof transfer.
//
// The native coordinator must explicitly bind all four inputs, original
// pre-auth/phone/factor authority and completion-only risk evidence. Replacement,
// OTP/TOTP replay advancement, capability/risk consumption and session revocation
// must commit atomically. Legacy email-reset and single-code accessors deny;
// construction enables no workflow or endpoint. Errors are redacted; no IO,
// callbacks, clocks or goroutines run. Immutable concurrent reads are safe.
func NewFeaturePhonePasswordResetInputCommand(spec FeatureCommandSpec, password primitive.Secret, proof capability.Proof, phoneCode, totpCode auth.OneTimeCode) (Command, error) {
	if password.Len() == 0 || password.Len() > 1<<20 {
		return Command{}, invalidFeatureCommand()
	}
	return newFeaturePhonePasswordResetCommand(spec, phonePasswordResetCommandState{input: true, password: password, proof: proof, phoneCode: phoneCode, totpCode: totpCode})
}

// NewFeaturePhonePasswordResetCommand retains the generated replacement verifier
// and all three original proof/code inputs for the same explicit phone profile.
// Verifier transport is 1..16384 visible ASCII bytes, unchanged, never plaintext.
// It does not screen or hash a password. Secret and authorization responsibilities,
// lifetimes and atomicity are otherwise identical to the input constructor.
// Preparation input and generated execution remain mutually exclusive; native
// owners must preserve every original input rather than issue substitute proof.
func NewFeaturePhonePasswordResetCommand(spec FeatureCommandSpec, encodedHash string, proof capability.Proof, phoneCode, totpCode auth.OneTimeCode) (Command, error) {
	if !validPasswordHashTransport(encodedHash) {
		return Command{}, invalidFeatureCommand()
	}
	return newFeaturePhonePasswordResetCommand(spec, phonePasswordResetCommandState{hash: strings.Clone(encodedHash), proof: proof, phoneCode: phoneCode, totpCode: totpCode})
}

func newFeaturePhonePasswordResetCommand(spec FeatureCommandSpec, state phonePasswordResetCommandState) (Command, error) {
	if !phonePasswordResetOperation(spec.Operation) || state.proof.ValidateBounds(32, 4096) != nil {
		return Command{}, invalidFeatureCommand()
	}
	for _, code := range []auth.OneTimeCode{state.phoneCode, state.totpCode} {
		if _, err := code.CommandDigest([32]byte{1}, "identity.command.validation"); err != nil {
			return Command{}, invalidFeatureCommand()
		}
	}
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	// Closure custody prevents private-wrapper formatting from traversing any
	// opaque code, proof or verifier backing storage through reflection.
	c.feature.phonePasswordReset = func() phonePasswordResetCommandState { return state }
	return c, nil
}

// BindPhonePasswordResetPreAuth retains the original browser-flow cookie with
// an exact joint phone-reset input or generated command. It returns a new
// immutable command, preserving every borrowed password/proof/code owner and
// leaving the original unchanged. Already-bound, legacy, mixed or zero commands
// and noncanonical cookies return zero Command and redacted InvalidInputError.
// Cookie syntax is canonical unpadded base64url for 32..64 bytes; only the native
// session owner may authenticate its original purpose, target and current row.
// Binding grants no verification or consumption authority and enables no flow.
func BindPhonePasswordResetPreAuth(original Command, cookie auth.BearerCredential) (Command, error) {
	state, ok := original.phonePasswordResetState(true)
	if !ok {
		state, ok = original.phonePasswordResetState(false)
	}
	if !ok || state.preAuthCookie.Token() != "" {
		return Command{}, invalidFeatureCommand()
	}
	frozen, err := freezeFeaturePreAuthCookie(cookie)
	if err != nil {
		return Command{}, err
	}
	state.preAuthCookie = frozen
	return newFeaturePhonePasswordResetCommand(original.feature.spec, state)
}

// PhonePasswordResetPreAuthCookie borrows only the exact original browser cookie
// retained by BindPhonePasswordResetPreAuth. Input and generated joint commands
// retain their distinct variants; generic Feature, PreAuthCookie and OneTimeCode
// remain closed rather than dropping a required factor. This is not proof of
// possession or current flow admission. Never log, serialize or persist Token;
// discard every borrowed secret-bearing copy after bounded native use. Zero,
// unbound, legacy and mixed commands return zero/false. No IO or callbacks run.
func (c Command) PhonePasswordResetPreAuthCookie() (auth.BearerCredential, bool) {
	state, ok := c.phonePasswordResetState(true)
	if !ok {
		state, ok = c.phonePasswordResetState(false)
	}
	if !ok || state.preAuthCookie.Token() == "" {
		return auth.BearerCredential{}, false
	}
	return state.preAuthCookie, true
}

func phonePasswordResetOperation(op FeatureOperation) bool {
	return op == (FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: FeatureRecordRequired})
}

func (c Command) phonePasswordResetState(input bool) (phonePasswordResetCommandState, bool) {
	f := c.feature
	if f == nil || f.phonePasswordReset == nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil || c.identifier != nil || c.privacy != nil || f.code != nil || f.recovery != nil || f.preAuthCookie != nil || f.sessionToken != nil || f.passwordHash != nil || f.passwordChange != nil || f.passwordReset != nil || f.passwordResetInput != nil || f.passwordSignin != nil || f.passwordSignup != nil || f.passwordSignupInput != nil || !phonePasswordResetOperation(f.spec.Operation) {
		return phonePasswordResetCommandState{}, false
	}
	state := f.phonePasswordReset()
	if state.input != input {
		return phonePasswordResetCommandState{}, false
	}
	return state, true
}

// PhonePasswordResetInputFeature returns an independently owned secret-free
// projection only for original joint phone recovery preparation. Zero, mixed,
// generated and legacy commands deny. Metadata survives terminal owner use but
// never conveys authority or permission to generate a replacement verifier.
func (c Command) PhonePasswordResetInputFeature() (FeatureCommandSpec, bool) {
	if _, ok := c.phonePasswordResetState(true); !ok {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PhonePasswordResetInputCustody borrows the original password, canonical reset
// proof, phone OTP and independent TOTP together, in that order. Presence is
// structural only; recheck all owner lifetimes and native authority during use.
// Never log, serialize or persist this tuple. Zero/mixed/other variants deny.
func (c Command) PhonePasswordResetInputCustody() (primitive.Secret, capability.Proof, auth.OneTimeCode, auth.OneTimeCode, bool) {
	s, ok := c.phonePasswordResetState(true)
	return s.password, s.proof, s.phoneCode, s.totpCode, ok
}

// PhonePasswordResetFeature returns independently owned secret-free metadata
// only for the generated joint phone recovery command. Input/legacy/mixed/zero
// variants deny. Returned values are trusted adapter input, not public output.
func (c Command) PhonePasswordResetFeature() (FeatureCommandSpec, bool) {
	if _, ok := c.phonePasswordResetState(false); !ok {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PhonePasswordResetCustody borrows the replacement verifier, canonical reset
// proof, phone OTP and independent TOTP together, in that order. It authenticates
// nothing and grants no transaction authority. Proof aliases share terminal
// transfer; Go cannot erase immutable verifier/code strings completely. Discard
// all secret-bearing copies after bounded use and keep only code-free recovery.
func (c Command) PhonePasswordResetCustody() (string, capability.Proof, auth.OneTimeCode, auth.OneTimeCode, bool) {
	s, ok := c.phonePasswordResetState(false)
	return s.hash, s.proof, s.phoneCode, s.totpCode, ok
}
