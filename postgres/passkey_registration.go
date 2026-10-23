package postgres

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// PasskeyRegistrationIntent describes one prospective passkey-only account.
// Creation must contain already admitted attributes and a trusted generated
// user ID. Credential is an initial passkey-owned reference, not WebAuthn key
// material. Neither value proves registration, user verification or permission
// to create an account. The original anonymous-flow command remains the sole
// durable operation; Creation uses the structural kernel shape for validation.
type PasskeyRegistrationIntent struct {
	Creation   identity.CreateUserCommand
	Credential identity.CredentialRef
}

func invalidPasskeyRegistration() error {
	return identity.InvalidInputError{Field: "passkey_registration"}
}

// PasskeyRegistrationFields freezes the complete kernel-owned prospective
// creation into the original native command. It neither creates an identity
// nor grants authentication. The exact registration.user field also binds the
// protocol participant's prospective subject before a durable account exists.
// Attributes must already satisfy the identity field policy; their bounded
// commitment is not a substitute for authorization or canonicalization.
// Returned fields own their values and contain no password or authenticator.
func PasskeyRegistrationFields(s PasskeyRegistrationIntent) ([]identity.FeatureField, error) {
	command, err := identity.NewUserCreationCommand(s.Creation)
	if err != nil {
		return nil, invalidPasskeyRegistration()
	}
	creation, _ := command.CreateUser()
	b, credential := creation.Binding, s.Credential
	if b.ActorKind != authorization.SubjectServiceAccount || credential.Validate(b.TenantID, b.UserID) != nil || credential.Kind != identity.CredentialPasskey || credential.Owner != "passkey" || credential.Version != 1 {
		return nil, invalidPasskeyRegistration()
	}
	attributes := make(map[string][]byte, len(creation.Attributes))
	for _, attribute := range creation.Attributes {
		encoded, err := encodeAttribute(attribute.Value)
		if err != nil {
			return nil, invalidPasskeyRegistration()
		}
		attributes[attribute.Name] = encoded
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("identity-passkey-registration-attributes-v1\x00"))
	_, _ = hash.Write(cborMap(attributes))
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "registration." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "registration." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{
		text("user", string(b.UserID)), text("schema", b.SchemaID), number("schema-version", uint64(b.SchemaVersion)),
		{Name: "registration.attributes", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: hash.Sum(nil)}},
		text("credential", string(credential.ID)), text("credential-owner", credential.Owner),
		number("credential-kind", uint64(credential.Kind)), number("credential-version", credential.Version),
	}, nil
}

// PasskeyRegistrationDigest commits the complete kernel-owned prospective field
// set under this exact registration profile. It is structural intent, not a
// keyed command fingerprint, a WebAuthn result or proof of successful creation.
func PasskeyRegistrationDigest(s PasskeyRegistrationIntent) ([32]byte, error) {
	fields, err := PasskeyRegistrationFields(s)
	if err != nil {
		return [32]byte{}, err
	}
	encoded := make(map[string][]byte, len(fields))
	for _, field := range fields {
		encoded[field.Name], err = encodeFeatureValue(field.Value)
		if err != nil {
			return [32]byte{}, invalidPasskeyRegistration()
		}
	}
	return sha256.Sum256(cborMap(map[string][]byte{
		"profile": cborText("identity-passkey-registration-intent-v1"), "fields": cborMap(encoded),
	})), nil
}

// Format prevents disclosure of prospective account attributes and scope.
func (PasskeyRegistrationIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasskeyRegistrationIntent(redacted)")
}

// MarshalJSON rejects implicit export of prospective account creation.
func (PasskeyRegistrationIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidPasskeyRegistration()
}
