package identity

import (
	"strings"

	"github.com/faustbrian/go-authentication/v2"
)

// NewFeaturePasswordSignupCommand freezes prepared encoded verifier material
// and the original pre-auth cookie in paired opaque custody. The closed native
// profile is identity/password, identity.password.signup, password-signup v1,
// record omitted, with explicit user or anonymous-flow scope. Hash transport
// is exactly 1..16384 visible ASCII bytes; cookie transport follows
// NewFeaturePreAuthCommand. Neither is normalized. Never pass plaintext here.
//
// This is transport, not hash-policy/HIBP approval, flow possession, risk
// admission, field permission or authentication. The native password owner
// must independently validate preparation, reserve the original flow/risk,
// bind both custody values into keyed intent and commit all required effects
// under the sole coordinator. No IO, callbacks, clocks or goroutines run.
// Legacy accessors reject this disjoint variant rather than dropping secrets.
// Invalid input returns zero Command and redacted InvalidInputError. Copies
// share immutable custody and support concurrent reads; discard them after
// bounded use. Go cannot guarantee erasure of immutable verifier/bearer strings.
func NewFeaturePasswordSignupCommand(spec FeatureCommandSpec, encodedHash string, cookie authentication.BearerCredential) (Command, error) {
	if !passwordSignupOperation(spec.Operation) || !validPasswordHashTransport(encodedHash) {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeaturePreAuthCommand(spec, cookie)
	if err != nil {
		return Command{}, err
	}
	hash, bearer := strings.Clone(encodedHash), *c.feature.preAuthCookie
	c.feature.preAuthCookie = nil
	// Closures prevent unsupported formatting reflection from walking secrets.
	c.feature.passwordSignup = func() (string, authentication.BearerCredential) { return hash, bearer }
	return c, nil
}

func passwordSignupOperation(op FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.signup" && op.SchemaID == "password-signup" && op.SchemaVersion == 1 && op.RecordRequirement == FeatureRecordOmitted && op.SubjectRequirement <= FeatureSubjectAnonymousFlow
}

func (c Command) validPasswordSignupVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordSignup != nil && c.feature.passwordSignin == nil && c.feature.passwordChange == nil && c.feature.passwordHash == nil && c.feature.code == nil && c.feature.preAuthCookie == nil && c.feature.sessionToken == nil && passwordSignupOperation(c.feature.spec.Operation)
}

// PasswordSignupFeature returns a separately owned secret-free metadata
// projection only for native signup custody. Zero, ordinary, mixed and other
// variants deny. Projection mutation cannot alter retained input. Success
// grants no execution, authentication or preparation authority. No IO runs.
func (c Command) PasswordSignupFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordSignupVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordSignupCustody borrows both original prepared hash and pre-auth bearer
// together for bounded native fingerprinting and owner validation. Zero, mixed
// and other variants return empty/false. Never serialize, log or retain these
// values in a kernel journal or public response. Hash storage is password-owned;
// recovery uses secret-free correlation, not this command. Borrowing provides
// no HIBP provenance, cookie possession, flow consumption or current authority.
func (c Command) PasswordSignupCustody() (string, authentication.BearerCredential, bool) {
	if !c.validPasswordSignupVariant() {
		return "", authentication.BearerCredential{}, false
	}
	hash, cookie := c.feature.passwordSignup()
	return hash, cookie, true
}
