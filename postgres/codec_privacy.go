package postgres

import identity "github.com/faustbrian/go-identity"

// The core owns the closed deterministic intent encoding. Bind that complete
// intent without inventing a second privacy protocol or storing its correlated
// session/cut-selection metadata. The original authenticated envelope is also
// keyed: even a different signature over the same header/payload is distinct
// submitted proof custody. Existing command codecs retain their original bytes.
// This is private claim encoding, not validation of current proof/session time,
// proof consumption, snapshot capture or public coordinator admission.
func encodePrivacy(c identity.PrivacyExportRequestCommand, key [32]byte) (map[string][]byte, error) {
	intent, err := identity.PrivacyExportIntentDigest(c)
	if err != nil {
		return nil, codecError()
	}
	envelope := c.Proof.EnvelopeDigest()
	if envelope == ([32]byte{}) {
		return nil, codecError()
	}
	intentBinding, err := commandSecret(key, "privacy.intent", intent[:], 32)
	if err != nil {
		return nil, err
	}
	proof, err := encodeCommandProof(c.Proof, key)
	if err != nil {
		return nil, err
	}
	envelopeBinding, err := commandSecret(key, "privacy.proof-envelope", envelope[:], 32)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"intent": cborBytes(intentBinding), "proof": proof, "proof_envelope": cborBytes(envelopeBinding)}, nil
}
