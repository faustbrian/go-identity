package identity

import (
	"github.com/faustbrian/go-authentication"
	primitive "github.com/faustbrian/go-password"
)

// NewFeaturePasswordSigninCommand freezes structural signin metadata with the
// existing primitive-owned password and original pre-auth cookie. The closed
// native profile is identity/password, identity.password.signin, password-signin
// v1, record-omitted, with explicit user or anonymous-flow scope. This internal
// adapter schema is distinct from the public request schema. Cookie transport
// uses NewFeaturePreAuthCommand's canonical 32..64-byte base64url bounds.
//
// Password length must be 1..1 MiB. No bytes are borrowed, copied, normalized,
// hashed or compared; copies retain the same Secret owner. The caller must
// Destroy that owner after bounded native execution, including failure. Length
// validation is not a liveness lease: destruction invalidates later borrowing.
// Construction grants no authentication, flow possession or execution authority.
// The native password owner must perform actual comparison, policy/current
// fences, keyed intent binding and same-commit effects under the coordinator.
//
// Legacy Feature/OTP/hash/change/bearer accessors reject this disjoint variant
// rather than silently omitting the password from intent. Only the paired
// PasswordSigninFeature and PasswordSigninCustody accessors select it. Recovery
// must use secret-free correlation, never this command. Invalid inputs return
// zero Command and redacted InvalidInputError. No IO or callbacks run.
func NewFeaturePasswordSigninCommand(spec FeatureCommandSpec, password primitive.Secret, cookie authentication.BearerCredential) (Command, error) {
	if !passwordSigninOperation(spec.Operation) || password.Len() == 0 || password.Len() > 1<<20 {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeaturePreAuthCommand(spec, cookie)
	if err != nil {
		return Command{}, err
	}
	frozen := *c.feature.preAuthCookie
	c.feature.preAuthCookie = nil
	// Closure custody prevents unsupported fmt verbs on private wrappers from
	// traversing bearer bytes while preserving the existing shared Secret owner.
	c.feature.passwordSignin = func() (primitive.Secret, authentication.BearerCredential) { return password, frozen }
	return c, nil
}

func passwordSigninOperation(op FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.signin" && op.SchemaID == "password-signin" && op.SchemaVersion == 1 && op.RecordRequirement == FeatureRecordOmitted && op.SubjectRequirement <= FeatureSubjectAnonymousFlow
}

func (c Command) validPasswordSigninVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordSignin != nil && c.feature.passwordHash == nil && c.feature.passwordChange == nil && c.feature.code == nil && c.feature.preAuthCookie == nil && c.feature.sessionToken == nil && passwordSigninOperation(c.feature.spec.Operation)
}

// PasswordSigninFeature returns an owned secret-free projection for the native
// password owner. Zero, mixed and other variants return false. Destruction of
// the password owner leaves metadata intact but grants no right to execute.
// Mutating returned fields cannot alter retained intent. No IO runs.
func (c Command) PasswordSigninFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordSigninVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordSigninCustody lends the original primitive Secret and pre-auth bearer
// together to native fingerprinting/comparison. Zero, mixed and other variants
// return zero values and false. Secret copies share terminal destruction and
// concurrency rules; the borrower must check/use its live owner, never interpret
// true as successful password comparison. Never log, persist or serialize the
// borrowed bearer, password bytes or this command. No IO or callbacks run.
func (c Command) PasswordSigninCustody() (primitive.Secret, authentication.BearerCredential, bool) {
	if !c.validPasswordSigninVariant() {
		return primitive.Secret{}, authentication.BearerCredential{}, false
	}
	p, b := c.feature.passwordSignin()
	return p, b, true
}
