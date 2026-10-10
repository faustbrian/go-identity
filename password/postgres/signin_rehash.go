package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"reflect"
	"strings"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

// This commitment binds salted replacement material into the existing keyed
// command fingerprint. It is not a verifier, proof or independent journal.
func signinRehashCommitment(hash primitive.EncodedHash) identity.FeatureField {
	digest := sha256.Sum256([]byte("identity-password-signin-rehash-material-v1\x00" + hash.String()))
	return identity.FeatureField{Name: "password.rehash.commitment", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}
}

// Rehash changes only the representation of a successfully compared password.
// It retains the original signin risk decision. Password establishment still
// uses the HIBP-screened signup/change/reset preparation contracts.
func (s *SigninService) prepareSigninRehash(ctx context.Context, secret primitive.Secret) (hash primitive.EncodedHash, err error) {
	defer func() {
		if recover() != nil {
			hash, err = primitive.EncodedHash{}, password.ErrPasswordWork
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, s.c.Verifier.Timeout)
	defer cancel()
	err = secret.Use(func(raw []byte) error {
		var e error
		hash, e = s.c.Verifier.Primitive.Hash(bounded, raw)
		return e
	})
	if err != nil || bounded.Err() != nil || !signinCurrentHash(hash, s.c.Repository.HashPolicy) {
		return primitive.EncodedHash{}, readerFailure(bounded)
	}
	return hash, nil
}

func signinCurrentHash(hash primitive.EncodedHash, policy primitive.Policy) bool {
	if policy.Algorithm() == "" || len(hash.String()) == 0 || uint64(len(hash.String())) > uint64(policy.Limits().EncodedHashBytes) {
		return false
	}
	parsed, err := primitive.ParseEncodedHash(hash.String(), policy.Limits())
	return err == nil && parsed.Algorithm() == policy.Algorithm() && (parsed.Algorithm() == primitive.Argon2id && parsed.Argon2idParameters() == policy.Argon2idParameters() || parsed.Algorithm() == primitive.Bcrypt && parsed.BcryptCost() == policy.BcryptCost())
}

func (p *signinPhase) validateRehashFields(fields []identity.FeatureField) error {
	expected := map[string]identity.FeatureValue{}
	if p.upgrade != nil {
		if !signinCurrentHash(p.replacement, p.hashPolicy) {
			return password.ErrPasswordWork
		}
		metadata, err := kernel.PasswordHashUpgradeFields(*p.upgrade)
		if err != nil {
			return password.ErrPasswordWork
		}
		metadata = append(metadata, signinRehashCommitment(p.replacement))
		for _, f := range metadata {
			expected[f.Name] = f.Value
		}
	} else if p.replacement.String() != "" {
		return password.ErrPasswordWork
	}
	for _, f := range fields {
		if strings.HasPrefix(f.Name, "session.result.") {
			continue
		}
		value, ok := expected[f.Name]
		if !ok || !reflect.DeepEqual(value, f.Value) {
			return password.ErrPasswordWork
		}
		delete(expected, f.Name)
	}
	if len(expected) != 0 {
		return password.ErrPasswordWork
	}
	return nil
}
