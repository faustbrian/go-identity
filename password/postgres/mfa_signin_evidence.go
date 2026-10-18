package passwordpostgres

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

const mfaSigninPrimaryProfile = "identity-password-mfa-primary-v1"
const usernameMFASigninPrimaryProfile = "identity-username-mfa-primary-v1"

// This owner-native non-final record is deliberately not SignedSignInRecord.
// It cannot enter SignInSource or mint an AuthenticatedProof. Only the password
// comparison owner may create it, in the challenge transaction; its canonical
// digest binds the existing continuation, not another command/replay journal.
type mfaSigninPrimary struct {
	Profile                                string
	State                                  auth.SignInState
	Issuer, Environment                    string
	Proof                                  auth.Proof
	ProofVersion                           uint64
	CredentialID                           string
	CredentialVersion                      uint64
	IdentifierID                           identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	Authority                              session.AuthoritySnapshotSpec
	KeyID                                  string
	Signature                              []byte
}

func mfaSigninPrimaryFrame(r mfaSigninPrimary) ([]byte, error) {
	if _, err := identity.ParseIdentifierID(string(r.IdentifierID)); err != nil || r.IdentifierVersion == 0 || r.VerificationVersion == 0 {
		return nil, password.ErrPasswordWork
	}
	if _, err := session.NewAuthoritySnapshot(r.Authority); err != nil || r.Authority.Factor.Present || r.Authority.Organization.Present || r.Authority.Passkey.Present {
		return nil, password.ErrPasswordWork
	}
	if r.Profile != mfaSigninPrimaryProfile && r.Profile != usernameMFASigninPrimaryProfile || r.State != auth.SignInStateChallengeRequired || !reauthenticationText(r.Issuer, 128) || !reauthenticationText(r.Environment, 128) || !reauthenticationText(r.CredentialID, 128) || !reauthenticationText(r.KeyID, 128) || r.ProofVersion == 0 || r.CredentialVersion == 0 || r.Proof.Method != "password" || r.Proof.Assurance != auth.AssuranceSingleFactor || r.Proof.Purpose != session.PasswordMFAPrimaryPurpose || r.Proof.ExpiresAt.Sub(r.Proof.IssuedAt) > 5*time.Minute {
		return nil, password.ErrPasswordWork
	}
	if _, err := identity.ParseCommandID(string(r.Proof.ID)); err != nil {
		return nil, password.ErrPasswordWork
	}
	proof, err := auth.NewProof(auth.ProofSpec(r.Proof))
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	r.Proof = proof
	r.Proof.IssuedAt, r.Proof.ExpiresAt = proof.IssuedAt.UTC(), proof.ExpiresAt.UTC()
	r.Signature = nil
	wire, err := json.Marshal(r)
	if err != nil || len(wire) > maximumSigninRecordBytes {
		return nil, password.ErrPasswordWork
	}
	// The distinct domain and non-final purpose prevent this signature from
	// authenticating an upstream completed-signin record, even after retagging.
	domain := "golib/identity/password/mfa-primary-v1\x00"
	if r.Profile == usernameMFASigninPrimaryProfile {
		// Preserve installed password signatures while binding username's exact
		// original flow under its own non-final comparison-evidence domain.
		domain = "golib/identity/username/mfa-primary-v1\x00"
	}
	return append([]byte(domain), wire...), nil
}

func (k SigninSigningKey) signMFAPrimary(r mfaSigninPrimary) (mfaSigninPrimary, error) {
	if k.applyPrimary == nil {
		return mfaSigninPrimary{}, password.ErrPasswordWork
	}
	return k.applyPrimary(r)
}

// Original storage is closed canonical framing. This is not a SignInSource
// variant: the completed-authentication decoder rejects this entire grammar.
func encodeMFASigninPrimary(r mfaSigninPrimary) ([]byte, [32]byte, error) {
	frame, err := mfaSigninPrimaryFrame(r)
	if err != nil || len(r.Signature) != ed25519.SignatureSize {
		return nil, [32]byte{}, password.ErrPasswordWork
	}
	clear(frame)
	r.Proof.IssuedAt, r.Proof.ExpiresAt = r.Proof.IssuedAt.UTC(), r.Proof.ExpiresAt.UTC()
	wire, err := json.Marshal(r)
	if err != nil || len(wire) > maximumSigninRecordBytes {
		return nil, [32]byte{}, password.ErrPasswordWork
	}
	return wire, sha256.Sum256(wire), nil
}

// Authentication of retained non-final evidence never renews time, changes
// state, performs current admission or constructs an AuthenticatedProof.
func decodeMFASigninPrimary(wire []byte, keys map[string]ed25519.PublicKey, issuer, environment string, id auth.ProofID, tenant, user string) (mfaSigninPrimary, [32]byte, error) {
	deny := func() (mfaSigninPrimary, [32]byte, error) {
		return mfaSigninPrimary{}, [32]byte{}, password.ErrPasswordWork
	}
	if len(wire) == 0 || len(wire) > maximumSigninRecordBytes {
		return deny()
	}
	var r mfaSigninPrimary
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Issuer != issuer || r.Environment != environment || r.Proof.ID != id || r.Proof.Tenant != tenant || r.Proof.Subject != user {
		return deny()
	}
	canonical, digest, err := encodeMFASigninPrimary(r)
	if err != nil || !bytes.Equal(canonical, wire) {
		return deny()
	}
	defer clear(canonical)
	frame, err := mfaSigninPrimaryFrame(r)
	if err != nil {
		return deny()
	}
	defer clear(frame)
	key := keys[r.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, r.Signature) {
		return deny()
	}
	return r, digest, nil
}

func (mfaSigninPrimary) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.MFAPrimary(redacted)")
}
