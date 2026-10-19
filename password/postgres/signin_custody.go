package passwordpostgres

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// SigninSigningKey owns immutable Ed25519 custody for the native password
// workflow. No public signing operation or private-key projection is exposed.
// Copies share immutable custody and support concurrent calls. The deployment
// owns key rotation and disposal of its original input buffer.
type SigninSigningKey struct {
	apply        func(auth.SignedSignInRecord) (auth.SignedSignInRecord, error)
	applyPrimary func(mfaSigninPrimary) (mfaSigninPrimary, error)
	public       func() (string, ed25519.PublicKey)
}

// NewSigninSigningKey copies an internally consistent complete Ed25519 key and
// a bounded visible-ASCII identifier. It performs no IO or authentication.
// Malformed input returns ErrPasswordWork and a zero owner. Use independent
// signing material, not password, risk, cookie or session lookup keys.
func NewSigninSigningKey(id string, key ed25519.PrivateKey) (SigninSigningKey, error) {
	if !reauthenticationText(id, 128) || len(key) != ed25519.PrivateKeySize {
		return SigninSigningKey{}, password.ErrPasswordWork
	}
	owned := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(owned, key) {
		clear(owned)
		return SigninSigningKey{}, password.ErrPasswordWork
	}
	id = strings.Clone(id)
	return SigninSigningKey{
		applyPrimary: func(r mfaSigninPrimary) (mfaSigninPrimary, error) {
			r.KeyID, r.Signature = id, nil
			frame, err := mfaSigninPrimaryFrame(r)
			if err != nil {
				return mfaSigninPrimary{}, password.ErrPasswordWork
			}
			defer clear(frame)
			proof, err := auth.NewProof(auth.ProofSpec(r.Proof))
			if err != nil {
				return mfaSigninPrimary{}, password.ErrPasswordWork
			}
			r.Proof = proof
			r.Issuer, r.Environment, r.CredentialID = strings.Clone(r.Issuer), strings.Clone(r.Environment), strings.Clone(r.CredentialID)
			r.Signature = ed25519.Sign(owned, frame)
			return r, nil
		},
		public: func() (string, ed25519.PublicKey) {
			return id, ed25519.PublicKey(slices.Clone(owned[ed25519.SeedSize:]))
		},
		apply: func(r auth.SignedSignInRecord) (auth.SignedSignInRecord, error) {
			// Only this workflow's actual single-factor password result may be
			// signed. Upstream framing remains the structural proof authority.
			if r.State != auth.SignInStateAuthenticated || r.Proof.Method != "password" || r.Proof.Assurance != auth.AssuranceSingleFactor || r.Proof.Purpose != "session-issue" || r.ProofVersion == 0 || r.CredentialVersion == 0 {
				return auth.SignedSignInRecord{}, password.ErrPasswordWork
			}
			r.KeyID, r.Signature = id, nil
			frame, err := r.SigningBytes()
			if err != nil {
				return auth.SignedSignInRecord{}, password.ErrPasswordWork
			}
			r.Signature = ed25519.Sign(owned, frame)
			return r, nil
		},
	}, nil
}

func (k SigninSigningKey) sign(r auth.SignedSignInRecord) (auth.SignedSignInRecord, error) {
	if k.apply == nil {
		return auth.SignedSignInRecord{}, password.ErrPasswordWork
	}
	return k.apply(r)
}

// Format redacts key custody for every formatting verb.
func (SigninSigningKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.SigninSigningKey(redacted)")
}

// MarshalJSON rejects implicit key export.
func (SigninSigningKey) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText rejects implicit text and map-key export.
func (SigninSigningKey) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// This pre-comparison check preserves the original intent and cookie binding.
// It grants no authority: the protected native effect must still lock/fence
// current state and consume the original pre-auth in the session transaction.
func admitSigninFlow(r password.SigninRequest, flow session.PreAuthTransaction, key session.DigestKey, policyID string, policyVersion uint64, now time.Time) error {
	spec, err := flow.Bindings()
	if err != nil {
		return password.ErrPasswordWork
	}
	b := spec.Binding
	i := b.Intent
	action := string(r.Caller.Request.Action)
	actualRemember, rememberErr := r.Remember.Bindings()
	originalRemember, originalErr := i.Remember.Bindings()
	if b.ID != r.PreAuthID || i.TenantID != r.TenantID || (action != "identity.password.signin" && action != "identity.username.signin" && action != "identity.phone.password-signin") || i.Action != action || i.Origin != r.Origin || i.CallbackURL != r.CallbackURL || i.PolicyID != policyID || i.PolicyVersion != policyVersion || rememberErr != nil || originalErr != nil || actualRemember != originalRemember {
		return password.ErrPasswordWork
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return password.ErrPasswordWork
	}
	digest, err := token.PreAuthDigest(key, b)
	if err != nil || flow.Check(now, b, digest) != nil {
		return password.ErrPasswordWork
	}
	return nil
}
