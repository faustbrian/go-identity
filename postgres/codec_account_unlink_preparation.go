package postgres

import identity "github.com/faustbrian/go-identity"

// This maps original intent, not a generated grant. Password-proof metadata
// and session possession must still be authenticated by their native owners;
// a canonical fingerprint is neither authority nor one-use consumption.
func encodeAccountUnlinkPreparation(command identity.Command, key [32]byte) (map[string][]byte, error) {
	spec, bearer, ok := command.AccountUnlinkPreparationInput()
	if !ok {
		return nil, codecError()
	}
	counters, err := encodeAccountCommandCounters(spec.Counters, key, "account.unlink.counter.network")
	if err != nil {
		return nil, err
	}
	payload := encodeAccountUnlinkIntent(spec.Change, spec.SessionID, spec.SessionVersion, spec.RevokeProvider)
	payload["preparation_profile"] = cborText("account-unlink-password-v1")
	payload["factor_authority_version"] = cborUint(spec.FactorAuthorityVersion)
	if spec.CSRFCommitment != ([32]byte{}) {
		payload["csrf_commitment"] = cborBytes(spec.CSRFCommitment[:])
	}
	payload["protected_counters"] = counters
	secret := []byte(bearer.Token())
	digest, err := commandSecret(key, "account.unlink.password.original-session", secret, 86)
	clear(secret)
	if err != nil {
		return nil, codecError()
	}
	payload["session_bearer"] = cborBytes(digest)
	p := spec.Primary.Proof
	// Signed password records retain nanosecond precision. Splitting seconds
	// and nanoseconds avoids UnixNano overflow and silent microsecond rounding.
	primary := cborMap(map[string][]byte{
		"id": cborText(string(p.ID)), "tenant": cborText(p.Tenant), "subject": cborText(p.Subject),
		"method": cborText(p.Method), "assurance": cborUint(uint64(p.Assurance)),
		"purpose": cborText(string(p.Purpose)), "audience": cborText(p.Audience),
		"issued_seconds": cborInt(p.IssuedAt.Unix()), "issued_nanoseconds": cborUint(uint64(p.IssuedAt.Nanosecond())),
		"expires_seconds": cborInt(p.ExpiresAt.Unix()), "expires_nanoseconds": cborUint(uint64(p.ExpiresAt.Nanosecond())),
		"session_id": cborText(spec.Primary.SessionID), "session_version": cborUint(spec.Primary.SessionVersion),
		"action": cborText(spec.Primary.Action),
	})
	digest, err = commandSecret(key, "account.unlink.password.original-primary", primary, 4096)
	clear(primary)
	if err != nil {
		return nil, codecError()
	}
	payload["password_primary"] = cborBytes(digest)
	return payload, nil
}
