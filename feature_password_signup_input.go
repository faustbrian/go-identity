package identity

import (
	"github.com/faustbrian/go-authentication/v2"
	primitive "github.com/faustbrian/go-password/v2"
)

// NewFeaturePasswordSignupInputCommand freezes original anonymous signup input
// before a verifier exists. Only identity/password, identity.password.signup,
// password-signup v1, record-omitted, anonymous-flow scope is supported. Cookie
// transport follows NewFeaturePreAuthCommand's canonical base64url bounds.
// Password length must be 1..1 MiB; registration policy may narrow these bounds.
//
// No password bytes are copied, normalized, hashed or compared. Copies share
// the primitive Secret owner, which the caller must Destroy after bounded use
// on every path. Destruction invalidates borrowing, not safe metadata. This
// command is preparation input, never the generated hash/cookie execution
// variant and never a recovery input. Construction grants no flow possession,
// password-policy approval, authorization or permission to execute. The native
// journal must bind original custody before acknowledged generation, then
// restore the generated verifier through NewFeaturePasswordSignupCommand.
//
// Only PasswordSignupInputFeature and PasswordSignupInputCustody select it.
// Legacy and generated-command accessors deny rather than discard the original
// password. Invalid input returns zero Command and redacted InvalidInputError.
// No IO, callbacks, clocks or goroutines run.
func NewFeaturePasswordSignupInputCommand(spec FeatureCommandSpec, password primitive.Secret, cookie authentication.BearerCredential) (Command, error) {
	if !passwordSignupOperation(spec.Operation) || spec.Operation.SubjectRequirement != FeatureSubjectAnonymousFlow || password.Len() == 0 || password.Len() > 1<<20 {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeaturePreAuthCommand(spec, cookie)
	if err != nil {
		return Command{}, err
	}
	frozen := *c.feature.preAuthCookie
	c.feature.preAuthCookie = nil
	// Closure custody keeps unsupported diagnostic reflection from traversing
	// bearer bytes while retaining the existing shared password lifetime.
	c.feature.passwordSignupInput = func() (primitive.Secret, authentication.BearerCredential) { return password, frozen }
	return c, nil
}

func (c Command) validPasswordSignupInputVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordSignupInput != nil && passwordSignupOperation(c.feature.spec.Operation) && c.feature.spec.Operation.SubjectRequirement == FeatureSubjectAnonymousFlow
}

// PasswordSignupInputFeature returns a separately owned secret-free original
// signup projection. Mutation cannot change retained intent. Zero, mixed and
// other variants deny. Metadata survives Secret destruction but grants no
// execution or recovery authority. No IO or callbacks run.
func (c Command) PasswordSignupInputFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordSignupInputVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordSignupInputCustody lends the original Secret and pre-auth bearer
// together for bounded native intent binding and preparation. Secret copies
// share terminal destruction and primitive concurrency rules. Success is not
// a liveness lease or password/flow verification: check the live owner when
// borrowing bytes. Never serialize, log or persist this custody. Zero, mixed
// and other variants return zero values and false. No IO or callbacks run.
func (c Command) PasswordSignupInputCustody() (primitive.Secret, authentication.BearerCredential, bool) {
	if !c.validPasswordSignupInputVariant() {
		return primitive.Secret{}, authentication.BearerCredential{}, false
	}
	p, b := c.feature.passwordSignupInput()
	return p, b, true
}
