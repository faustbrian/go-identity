package postgres

import (
	"encoding/base64"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

func encodeLink(s identity.AccountLinkCommand, key [32]byte) (map[string][]byte, error) {
	c := s.Change
	a := c.Account
	p := map[string][]byte{
		"mode": cborUint(uint64(c.Mode)), "account_id": cborText(string(a.ID)),
		"tenant_id": cborText(string(a.TenantID)), "user_id": cborText(string(a.UserID)),
		"provider": cborText(a.Provider), "account_version": cborUint(a.Version),
		"expected_user_version":        cborUint(c.ExpectedUserVersion),
		"expected_account_version":     cborUint(c.ExpectedAccountVersion),
		"expected_social_link_version": cborUint(c.ExpectedSocialLinkVersion),
		"expected_credential_version":  cborUint(c.ExpectedCredentialVersion),
	}
	issuer, e := commandSecret(key, "account.issuer", []byte(a.Issuer), 2048)
	if e != nil {
		return nil, e
	}
	p["issuer"] = cborBytes(issuer)
	subject, e := commandSecret(key, "account.subject", []byte(a.Subject), 512)
	if e != nil {
		return nil, e
	}
	p["subject"] = cborBytes(subject)
	if c.Reason != "" {
		p["reason"] = cborText(string(c.Reason))
	}
	if c.MatchedIdentifier != "" {
		p["matched_identifier"] = cborText(string(c.MatchedIdentifier))
		digest, e := commandSecret(key, "account.verified_identifier", []byte(c.VerifiedCanonicalIdentifier), 512)
		if e != nil {
			return nil, e
		}
		p["verified_identifier"] = cborBytes(digest)
		p["expected_identifier_authority_version"] = cborUint(c.ExpectedIdentifierAuthorityVersion)
		p["expected_identifier_version"] = cborUint(c.ExpectedIdentifierVersion)
		p["expected_verification_version"] = cborUint(c.ExpectedVerificationVersion)
	}
	if c.Method != nil {
		m := c.Method
		r := m.Credential
		method := map[string][]byte{"account_id": cborText(string(m.AccountID)), "usable": cborBool(m.Usable), "credential": cborMap(map[string][]byte{"id": cborText(string(r.ID)), "tenant_id": cborText(string(r.TenantID)), "user_id": cborText(string(r.UserID)), "kind": cborUint(uint64(r.Kind)), "owner": cborText(r.Owner), "version": cborUint(r.Version)})}
		if !m.ExpiresAt.IsZero() {
			if !postgresExactTime(m.ExpiresAt) {
				return nil, codecError()
			}
			method["expires_at"] = cborInt(m.ExpiresAt.UnixMicro())
		}
		p["method"] = cborMap(method)
	}
	if s.PreAuthTransactionID != "" {
		id, e := base64.RawURLEncoding.DecodeString(string(s.PreAuthTransactionID))
		if e != nil || len(id) != 16 {
			return nil, codecError()
		}
		p["pre_auth_id"] = cborBytes(id)
	} else {
		p["session_id"] = cborText(s.SessionID)
		p["session_version"] = cborUint(s.SessionVersion)
	}
	proof, e := encodeCommandProof(s.Proof, key)
	if e != nil {
		return nil, e
	}
	p["proof"] = proof
	return p, nil
}

func encodeUnlink(s identity.AccountUnlinkCommand, key [32]byte) (map[string][]byte, error) {
	c := s.Change
	proof, e := encodeCommandProof(s.Proof, key)
	if e != nil {
		return nil, e
	}
	return map[string][]byte{
		"tenant_id": cborText(string(c.TenantID)), "user_id": cborText(string(c.UserID)), "account_id": cborText(string(c.AccountID)),
		"expected_user_version": cborUint(c.ExpectedUserVersion), "expected_account_version": cborUint(c.ExpectedAccountVersion),
		"expected_social_link_version": cborUint(c.ExpectedSocialLinkVersion), "expected_credential_version": cborUint(c.ExpectedCredentialVersion),
		"session_id": cborText(s.SessionID), "session_version": cborUint(s.SessionVersion), "revoke_provider": cborBool(s.RevokeProvider), "proof": proof,
	}, nil
}

func encodeIdentifier(s identity.IdentifierCommand, key [32]byte) (map[string][]byte, error) {
	c := s.Change
	p := map[string][]byte{
		"tenant_id": cborText(string(c.TenantID)), "user_id": cborText(string(c.UserID)), "identifier_id": cborText(string(c.ID)), "action": cborUint(uint64(c.Action)),
		"expected_user_version": cborUint(c.ExpectedUserVersion), "expected_authority_version": cborUint(c.ExpectedAuthorityVersion),
		"session_id": cborText(s.SessionID), "session_version": cborUint(s.SessionVersion),
	}
	if c.ExpectedIdentifierVersion != 0 {
		p["expected_identifier_version"] = cborUint(c.ExpectedIdentifierVersion)
		p["expected_verification_version"] = cborUint(c.ExpectedVerificationVersion)
	}
	if c.Kind != "" {
		p["kind"] = cborText(string(c.Kind))
		digest, e := commandSecret(key, "identifier.canonical", []byte(c.CanonicalValue), 512)
		if e != nil {
			return nil, e
		}
		p["canonical_value"] = cborBytes(digest)
		if c.DisplayValue != "" {
			digest, e = commandSecret(key, "identifier.display", []byte(c.DisplayValue), 512)
			if e != nil {
				return nil, e
			}
			p["display_value"] = cborBytes(digest)
		}
	}
	proof, e := encodeCommandProof(s.Proof, key)
	if e != nil {
		return nil, e
	}
	p["proof"] = proof
	return p, nil
}

// The capability primitive owns its canonical authenticated payload encoding;
// the adapter neither serializes Command as JSON nor copies that protocol.
// Digest the whole bounded authority payload, including private caveats and
// correlation, rather than persisting unkeyed intent digests. Grant contains no
// bearer bytes. Header metadata is included so re-signing under another key or
// algorithm cannot silently change the submitted proof's command meaning.
// This observes a verified grant; it never verifies or consumes one-use state.
func encodeCommandProof(g capability.Grant, key [32]byte) ([]byte, error) {
	payload, e := capability.CanonicalPayload(g.Payload(), capability.DefaultLimits())
	if e != nil {
		return nil, codecError()
	}
	header := g.Header()
	if len(header.KeyID) > 256 {
		return nil, codecError()
	}
	authority := cborMap(map[string][]byte{"header": cborMap(map[string][]byte{"version": cborInt(int64(header.Version)), "type": cborText(header.Type), "algorithm": cborText(string(header.Algorithm)), "key_id": cborText(header.KeyID)}), "payload": cborBytes(payload)})
	digest, e := commandSecret(key, "proof.authority", authority, 20<<10)
	if e != nil {
		return nil, e
	}
	return cborBytes(digest), nil
}

func cborBool(v bool) []byte {
	if v {
		return []byte{0xf5}
	}
	return []byte{0xf4}
}
