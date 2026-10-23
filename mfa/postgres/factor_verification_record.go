package mfapostgres

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

const maximumFactorVerificationRecordBytes = 32768

// Original signed evidence is distinct from the current owner epoch. Only the
// native factor issuer may persist this record after locking and verifying the
// active factor. The epoch is trusted immutable MFA storage metadata, not a
// portable signed claim or a renewable authorization lease. Authentication's
// existing evidence-key validator authenticates Original; the protected
// consumer separately locks current factor authority and the one-use record.
type factorVerificationRecord struct {
	Schema                 uint32
	Original               auth.SignedReauthenticationRecord
	FactorAuthorityVersion uint64
}

func (factorVerificationRecord) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.factorVerificationRecord(redacted)"))
}

// This codec validates the closed native TOTP management profile, not the
// signature or current account/session/factor. Native issuance and one-use
// admission remain separate protected transitions; callers cannot insert
// evidence merely by constructing this private representation.
func encodeFactorVerificationRecord(r factorVerificationRecord) ([]byte, error) {
	return encodeNativeFactorVerificationRecord(r, 1, "totp")
}

// The explicit OTP profile has different storage/issuance ownership. Its
// schema discriminator prevents existing TOTP readers from reinterpreting it.
func encodeOTPFactorVerificationRecord(r factorVerificationRecord) ([]byte, error) {
	return encodeNativeFactorVerificationRecord(r, 2, "otp")
}

func encodeNativeFactorVerificationRecord(r factorVerificationRecord, schema uint32, method string) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, invalidAuthority() }
	p := r.Original.Proof
	profile := schema == 1 && method == "totp" || schema == 2 && method == "otp"
	purpose := nativeFactorEvidencePurpose(p.Proof.Purpose)
	if method == "otp" {
		purpose = p.Proof.Purpose == "identity.mfa.factor-update" || p.Proof.Purpose == "identity.mfa.disable"
	}
	if !profile || r.Schema != schema || r.FactorAuthorityVersion == 0 || p.Proof.Method != method || p.Proof.Assurance != auth.AssuranceMultiFactor || !purpose || p.Action != string(p.Proof.Purpose) || p.Proof.ExpiresAt.Sub(p.Proof.IssuedAt) > 5*time.Minute || r.Original.ProofVersion != 1 || len(r.Original.Signature) != ed25519.SignatureSize {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(p.Proof.ID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(r.Original.CredentialID); err != nil {
		return bad()
	}
	for _, id := range []string{p.Proof.Tenant, p.Proof.Subject} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return bad()
		}
	}
	if _, err := mfa.NewContinuationProof(p); err != nil {
		return bad()
	}
	if _, err := r.Original.SigningBytes(); err != nil {
		return bad()
	}
	wire, err := json.Marshal(r)
	if err != nil || len(wire) == 0 || len(wire) > maximumFactorVerificationRecordBytes {
		return bad()
	}
	return wire, nil
}

func nativeFactorEvidencePurpose(p auth.Purpose) bool {
	switch p {
	case "identity.mfa.recovery-regenerate", "identity.mfa.factor-update", "identity.mfa.disable", "identity.email.change-request":
		return true
	default:
		return false
	}
}

func decodeFactorVerificationRecord(id auth.ProofID, tenant, user string, wire []byte) (factorVerificationRecord, error) {
	return decodeNativeFactorVerificationRecord(id, tenant, user, wire, 1, "totp")
}

func decodeOTPFactorVerificationRecord(id auth.ProofID, tenant, user string, wire []byte) (factorVerificationRecord, error) {
	return decodeNativeFactorVerificationRecord(id, tenant, user, wire, 2, "otp")
}

func decodeNativeFactorVerificationRecord(id auth.ProofID, tenant, user string, wire []byte, schema uint32, method string) (factorVerificationRecord, error) {
	bad := func() (factorVerificationRecord, error) {
		return factorVerificationRecord{}, invalidAuthority()
	}
	if len(wire) == 0 || len(wire) > maximumFactorVerificationRecordBytes {
		return bad()
	}
	var r factorVerificationRecord
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Original.Proof.Proof.ID != id || r.Original.Proof.Proof.Tenant != tenant || r.Original.Proof.Proof.Subject != user {
		return bad()
	}
	canonical, err := encodeNativeFactorVerificationRecord(r, schema, method)
	if err != nil || !bytes.Equal(canonical, wire) {
		return bad()
	}
	return r, nil
}
