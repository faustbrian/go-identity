package mfapostgres

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	password "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// PhoneRecoveryTOTPVerifier owns transient cryptographic configuration, not a
// factor engine, attempt budget, session or transaction. Its envelope service
// is borrowed and must honor bounded contexts. Concurrent preparations are safe
// when that service is safe. Decryption happens only in Prepare, outside Work.
type PhoneRecoveryTOTPVerifier struct {
	crypto     *envelope.Service
	verifier   mfa.TOTPVerifier
	keyVersion uint32
}

// NewPhoneRecoveryTOTPVerifier retains the existing envelope service and copies
// a nonzero independent comparison key into the core verifier. Its positive
// version is retained in the comparison scope across rotation. It does no IO.
func NewPhoneRecoveryTOTPVerifier(crypto *envelope.Service, comparisonKey [32]byte, comparisonKeyVersion uint32) (*PhoneRecoveryTOTPVerifier, error) {
	if crypto == nil || comparisonKeyVersion == 0 {
		return nil, invalidAuthority()
	}
	v, err := mfa.NewTOTPVerifier(comparisonKey)
	if err != nil {
		return nil, err
	}
	return &PhoneRecoveryTOTPVerifier{crypto: crypto, verifier: v, keyVersion: comparisonKeyVersion}, nil
}

// PreparedPhoneRecoveryTOTP is owned plaintext custody for one exact original
// or generated phone-reset command. Copies share one terminal lifetime. Destroy
// is required after preparation even when execution never starts; verification
// also destroys it on every return. No plaintext/code/counter can be extracted.
// Verification is serial and must not race a caller's command-owner destruction.
type PreparedPhoneRecoveryTOTP struct {
	custody func() *preparedPhoneRecoveryTOTP
}
type preparedPhoneRecoveryTOTP struct {
	mu               sync.Mutex
	secret           password.Secret
	verifier         mfa.TOTPVerifier
	keyVersion       uint32
	snapshot         TOTPFactorSnapshot
	command          identity.Command
	until            time.Time
	input, destroyed bool
	done             chan struct{}
}

// A use moves Secret ownership out under the short custody lock. SQL and
// cryptography run without holding that lock; Destroy waits on done outside it.
type phoneRecoveryTOTPUse struct {
	secret     password.Secret
	verifier   mfa.TOTPVerifier
	keyVersion uint32
	snapshot   TOTPFactorSnapshot
	command    identity.Command
	until      time.Time
	input      bool
	done       chan struct{}
}

// Destroy terminally clears the owned primitive Secret for every alias. It is
// idempotent, including zero. It waits for an in-flight bounded verification.
func (p PreparedPhoneRecoveryTOTP) Destroy() {
	if p.custody == nil {
		return
	}
	s := p.custody()
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.destroyed {
		done := s.done
		s.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	s.destroyed = true
	secret, done := s.secret, s.done
	s.secret = password.Secret{}
	s.command = identity.Command{}
	s.mu.Unlock()
	secret.Destroy()
	if done != nil {
		close(done)
	}
}
func (p PreparedPhoneRecoveryTOTP) borrow() (*phoneRecoveryTOTPUse, error) {
	if p.custody == nil {
		return nil, invalidAuthority()
	}
	s := p.custody()
	if s == nil {
		return nil, invalidAuthority()
	}
	s.mu.Lock()
	if s.destroyed {
		s.mu.Unlock()
		return nil, invalidAuthority()
	}
	s.destroyed = true
	use := &phoneRecoveryTOTPUse{secret: s.secret, verifier: s.verifier, keyVersion: s.keyVersion, snapshot: s.snapshot, command: s.command, until: s.until, input: s.input, done: s.done}
	s.secret = password.Secret{}
	s.command = identity.Command{}
	s.mu.Unlock()
	return use, nil
}
func (s *phoneRecoveryTOTPUse) finish() {
	s.secret.Destroy()
	s.secret = password.Secret{}
	s.command = identity.Command{}
	if s.done != nil {
		close(s.done)
	}
}

// Prepare decrypts the exact encrypted snapshot before any coordinator locks.
// until is the original exclusive validity deadline selected by the native
// phone owner from its authenticated reset/pre-auth/risk authority; this helper
// cannot authenticate or renew it. It must be microsecond-exact. IO is bounded to five seconds or the earlier
// caller deadline. Preparation itself grants no permission: both native phases
// independently lock/recheck the full current factor fence and verify the actual
// original code at database time. Failed preparation clears all plaintext.
func (v *PhoneRecoveryTOTPVerifier) Prepare(ctx context.Context, snapshot TOTPFactorSnapshot, command identity.Command, until time.Time) (PreparedPhoneRecoveryTOTP, error) {
	if ctx == nil || v == nil || v.crypto == nil || v.keyVersion == 0 || snapshot.custody == nil {
		return PreparedPhoneRecoveryTOTP{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return PreparedPhoneRecoveryTOTP{}, err
	}
	m, err := snapshot.Metadata()
	if err != nil || !phoneRecoverySnapshot(m) || m.RowVersion == math.MaxUint64 || until.IsZero() || until.Year() < 1 || until.Year() > 9999 || until.Nanosecond()%1000 != 0 || !time.Now().Before(until) {
		return PreparedPhoneRecoveryTOTP{}, identity.ForbiddenError{}
	}
	_, input, err := phoneRecoveryCommand(command, m)
	if err != nil {
		return PreparedPhoneRecoveryTOTP{}, err
	}
	sealed, err := snapshot.Envelope()
	if err != nil {
		return PreparedPhoneRecoveryTOTP{}, err
	}
	binding, err := snapshot.EncryptionContext()
	if err != nil {
		return PreparedPhoneRecoveryTOTP{}, err
	}
	expected, err := totpEncryptionContext(m.TenantID, m.UserID, m.FactorID, m.EnrollmentVersion, m.Profile)
	if err != nil || !bytes.Equal(expected.AdditionalData(), binding.AdditionalData()) {
		return PreparedPhoneRecoveryTOTP{}, identity.ForbiddenError{}
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	plain, err := v.crypto.Decrypt(bounded, envelope.DecryptRequest{Envelope: sealed, Context: binding})
	defer clear(plain)
	if bounded.Err() != nil {
		return PreparedPhoneRecoveryTOTP{}, bounded.Err()
	}
	if err != nil || len(plain) < 20 || len(plain) > 128 {
		return PreparedPhoneRecoveryTOTP{}, identity.UnavailableError{}
	}
	secret, err := password.NewSecret(plain)
	if err != nil {
		return PreparedPhoneRecoveryTOTP{}, identity.UnavailableError{}
	}
	if !time.Now().Before(until) {
		secret.Destroy()
		return PreparedPhoneRecoveryTOTP{}, identity.ForbiddenError{}
	}
	s := &preparedPhoneRecoveryTOTP{secret: secret, verifier: v.verifier, keyVersion: v.keyVersion, snapshot: snapshot, command: command, input: input, until: until.UTC(), done: make(chan struct{})}
	return PreparedPhoneRecoveryTOTP{custody: func() *preparedPhoneRecoveryTOTP { return s }}, nil
}

func phoneRecoverySnapshot(m TOTPFactorMetadata) bool {
	return m.EnrollmentVersion > 0 && m.RowVersion > 0 && m.FactorAuthorityVersion > 0 && m.ContinuationID == "" && m.ContinuationVersion == 0 && m.ScopeDigest == ([32]byte{}) && m.Profile.Validate() == nil && (m.Replay.Used || m.Replay.LastStep == 0)
}

func phoneRecoveryCommand(c identity.Command, m TOTPFactorMetadata) (auth.OneTimeCode, bool, error) {
	f, input := c.PhonePasswordResetInputFeature()
	var code auth.OneTimeCode
	if input {
		_, _, _, code, _ = c.PhonePasswordResetInputCustody()
	} else {
		var ok bool
		f, ok = c.PhonePasswordResetFeature()
		if !ok {
			return code, false, invalidAuthority()
		}
		_, _, _, code, _ = c.PhonePasswordResetCustody()
	}
	if err := phoneRecoveryFactorSpec(f, m); err != nil {
		return auth.OneTimeCode{}, false, err
	}
	return code, input, nil
}

// Protected OTP checks expose only this code-free root-owned metadata. Reuse
// the same closed tuple/factor selection without manufacturing a command or
// borrowing either submitted code during a non-consuming check.
func phoneRecoveryFactorSpec(f identity.FeatureCommandSpec, m TOTPFactorMetadata) error {
	operation := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if f.Operation != operation || f.Binding.ValidateFor(operation) != nil || f.Binding.TenantID != m.TenantID || f.Binding.UserID != m.UserID {
		return identity.ForbiddenError{}
	}
	var id, enrollment, authority bool
	for _, field := range f.Fields {
		switch field.Name {
		case "phone.reset.factor-id":
			if id || field.Value.Kind != identity.FeatureText || field.Value.Text != m.FactorID {
				return identity.ForbiddenError{}
			}
			id = true
		case "phone.reset.factor-version":
			if enrollment || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != m.EnrollmentVersion {
				return identity.ForbiddenError{}
			}
			enrollment = true
		case "phone.reset.factor-authority-version":
			if authority || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != m.FactorAuthorityVersion {
				return identity.ForbiddenError{}
			}
			authority = true
		default:
			if strings.HasPrefix(field.Name, "phone.reset.factor-") {
				return identity.ForbiddenError{}
			}
		}
	}
	if !id || !enrollment || !authority {
		return identity.ForbiddenError{}
	}
	return nil
}

func (PreparedPhoneRecoveryTOTP) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.PreparedPhoneRecoveryTOTP(redacted)"))
}
func (PreparedPhoneRecoveryTOTP) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }
func (PreparedPhoneRecoveryTOTP) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
func (*PhoneRecoveryTOTPVerifier) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.PhoneRecoveryTOTPVerifier(redacted)"))
}
func (*PhoneRecoveryTOTPVerifier) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }
func (*PhoneRecoveryTOTPVerifier) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
