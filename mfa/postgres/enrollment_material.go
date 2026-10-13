package mfapostgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// Initial enrollment and replacement use the same cryptographic profile.
// Their callers separately admit the actual operation; this helper grants no
// authority and runs only outside protected database locks. Generation belongs
// to the existing retained preparation, never to retries or result recovery.
func generateEnrollmentMaterial(ctx context.Context, state *totpEnrollmentState, m PendingTOTPMetadata, generation uint64, count uint32) (output totpEnrollmentOutput, err error) {
	if state == nil || generation == 0 || count == 0 || count > 64 {
		return output, invalidEnrollment()
	}
	defer func() {
		if err != nil {
			clearEnrollmentOutput(&output)
		}
	}()
	pending, err := state.preparer.Prepare(ctx, TOTPEnrollmentPreparation{TenantID: m.TenantID, UserID: m.UserID, FactorID: m.FactorID, AuthorityVersion: m.AuthorityVersion, Profile: m.Profile, CreatedAt: m.CreatedAt, TTL: m.ExpiresAt.Sub(m.CreatedAt)})
	if err != nil {
		return output, err
	}
	sealed, err := pending.Envelope()
	if err != nil {
		return output, err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		return output, err
	}
	output = totpEnrollmentOutput{Schema: 1, RecoveryKeyVersion: state.config.RecoveryKeyVersion, Generation: generation, Meta: m, Envelope: wire}
	key := state.config.recoveryKey()
	defer clear(key[:])
	binding, err := enrollmentRecoveryBinding(m)
	if err != nil {
		return output, err
	}
	defer clear(binding)
	for range count {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			clear(raw)
			return output, identity.UnavailableError{}
		}
		encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
		base64.RawURLEncoding.Encode(encoded, raw)
		clear(raw)
		code, err := auth.NewRecoveryCode(string(encoded))
		if err != nil {
			clear(encoded)
			return output, identity.UnavailableError{}
		}
		digest, err := code.KeyedDigest(key, binding)
		if err != nil {
			clear(encoded)
			return output, identity.UnavailableError{}
		}
		output.Codes = append(output.Codes, encoded)
		output.Digests = append(output.Digests, digest)
	}
	return output, nil
}
