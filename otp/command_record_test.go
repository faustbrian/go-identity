package otp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/otp"
)

func TestCommandAttemptRecordRestoresOriginalServerIdentity(t *testing.T) {
	b, op := commandAttemptScope()
	i, _ := otp.NewAttemptIssuer(7, [32]byte{9})
	code, _ := auth.NewOneTimeCode("123456")
	a, err := i.PrepareForCommand(context.Background(), b, op, attemptContinuation(t), otp.AttemptModeConsume, 11, code)
	if err != nil {
		t.Fatal(err)
	}
	record, err := i.SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := i.RestoreForCommand(record, code)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := a.Recovery()
	recovery, _ := restored.Recovery()
	if recovery != original {
		t.Fatal("restore regenerated logical submission")
	}
	rb, rop, err := restored.CommandBinding()
	if err != nil || rb != b || rop != op {
		t.Fatal("original command changed", err)
	}
	wrong, _ := auth.NewOneTimeCode("654321")
	if _, err := i.RestoreForCommand(record, wrong); err == nil {
		t.Fatal("different submission accepted")
	}
}

func commandRecordFixture(t *testing.T) (otp.AttemptIssuer, otp.CommandAttemptRecord, auth.OneTimeCode) {
	t.Helper()
	b, op := commandAttemptScope()
	i, _ := otp.NewAttemptIssuer(7, [32]byte{9})
	code, _ := auth.NewOneTimeCode("123456")
	a, err := i.PrepareForCommand(context.Background(), b, op, attemptContinuation(t), otp.AttemptModeConsume, 11, code)
	if err != nil {
		t.Fatal(err)
	}
	r, err := i.SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	return i, r, code
}

func TestCommandRecordIndependentMACAndIdBinding(t *testing.T) {
	i, r, code := commandRecordFixture(t)
	// Literal profile oracle: no production scope/framing or signing helper.
	structural := []byte("identity-otp-command-scope-v1\x00")
	for _, s := range []string{"AQEBAQEBAQEBAQEBAQEBAQ", "tenant", "subject", "", "service", string(r.Binding.ActorKind), "identity.otp.signin", "policy", "identity-otp-signin", "correlation", "target", "identity/otp", "identity.otp.signin", "identity-otp-signin"} {
		structural = binary.BigEndian.AppendUint16(structural, uint16(len(s)))
		structural = append(structural, s...)
	}
	structural = binary.BigEndian.AppendUint64(structural, 1)
	structural = binary.BigEndian.AppendUint32(structural, 1)
	structural = append(structural, 0)
	structural = binary.BigEndian.AppendUint32(structural, 1)
	structural = append(structural, 2, 0)
	commandDigest := sha256.Sum256(structural)
	scope := []byte("identity-otp-code-scope-v1\x00")
	for _, s := range []string{"tenant", "signin", "subject", "email", "user@example.test", "challenge", "target"} {
		scope = binary.BigEndian.AppendUint16(scope, uint16(len(s)))
		scope = append(scope, s...)
	}
	scope = binary.BigEndian.AppendUint64(scope, 3)
	scope = binary.BigEndian.AppendUint64(scope, 4)
	cb, _ := r.Attempt.Continuation.Bindings()
	scope = append(scope, cb.Scope.AuthorizationBinding[:]...)
	v, _ := otp.NewVerifier(7, map[uint32][32]byte{7: {9}})
	digestScope, _ := r.Attempt.Continuation.DigestScope()
	lookup, err := v.ScopeDigest(digestScope, 7)
	if err != nil {
		t.Fatal(err)
	}
	lookupFrame := []byte("identity-otp-scope-digest-v1\x00")
	lookupFrame = binary.BigEndian.AppendUint32(lookupFrame, uint32(len(scope)))
	lookupFrame = append(lookupFrame, scope...)
	lookupFrame = binary.BigEndian.AppendUint32(lookupFrame, 7)
	lookupKey := [32]byte{9}
	lookupMAC := hmac.New(sha256.New, lookupKey[:])
	lookupMAC.Write(lookupFrame)
	if lookup.KeyVersion != 7 || !hmac.Equal(lookup.Value[:], lookupMAC.Sum(nil)) {
		t.Fatal("keyed scope digest drift")
	}
	frame := []byte("identity-otp-command-attempt-record-v1\x00")
	frame = binary.BigEndian.AppendUint32(frame, 7)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(scope)))
	frame = append(frame, scope...)
	frame = append(frame, string(r.Attempt.AttemptID)...)
	frame = append(frame, string(r.Attempt.Fingerprint)...)
	frame = append(frame, 2)
	frame = binary.BigEndian.AppendUint64(frame, 11)
	frame = append(frame, commandDigest[:]...)
	key := [32]byte{9}
	h := hmac.New(sha256.New, key[:])
	h.Write(frame)
	if !hmac.Equal(h.Sum(nil), r.Signature[:]) {
		t.Fatal("record MAC profile drift")
	}
	a, err := i.RestoreForCommand(r, code)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := i.SealForCommand(a)
	if err != nil || sealed.Signature != r.Signature || sealed.Attempt != r.Attempt {
		t.Fatal("restoration changed sealed identity")
	}
}

func TestCommandRecordTamperingAndKeyRetirementDeny(t *testing.T) {
	i, r, code := commandRecordFixture(t)
	changes := map[string]func(*otp.CommandAttemptRecord){
		"id": func(r *otp.CommandAttemptRecord) { r.Attempt.AttemptID = "AgICAgICAgICAgICAgICAg" },
		"zero-id": func(r *otp.CommandAttemptRecord) {
			r.Attempt.AttemptID = otp.AttemptID(base64.RawURLEncoding.EncodeToString(make([]byte, 16)))
		},
		"id-alphabet": func(r *otp.CommandAttemptRecord) { r.Attempt.AttemptID = "!!!!!!!!!!!!!!!!!!!!!!" },
		"id-length":   func(r *otp.CommandAttemptRecord) { r.Attempt.AttemptID = "x" },
		"fingerprint": func(r *otp.CommandAttemptRecord) {
			r.Attempt.Fingerprint = otp.AttemptFingerprint(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		},
		"fingerprint-alphabet": func(r *otp.CommandAttemptRecord) {
			r.Attempt.Fingerprint = otp.AttemptFingerprint(strings.Repeat("!", 43))
		},
		"fingerprint-length": func(r *otp.CommandAttemptRecord) { r.Attempt.Fingerprint = "x" },
		"version":            func(r *otp.CommandAttemptRecord) { r.Attempt.ExpectedVersion++ },
		"zero-version":       func(r *otp.CommandAttemptRecord) { r.Attempt.ExpectedVersion = 0 },
		"mode":               func(r *otp.CommandAttemptRecord) { r.Attempt.Mode = otp.AttemptModeCheck },
		"unknown-mode":       func(r *otp.CommandAttemptRecord) { r.Attempt.Mode = 99 },
		"key":                func(r *otp.CommandAttemptRecord) { r.Attempt.FingerprintKeyVersion++ },
		"command": func(r *otp.CommandAttemptRecord) {
			r.Binding.CommandID = "AgICAgICAgICAgICAgICAg"
			r.Attempt.CommandID = r.Binding.CommandID
		},
		"attempt-command":   func(r *otp.CommandAttemptRecord) { r.Attempt.CommandID = "AgICAgICAgICAgICAgICAg" },
		"tenant":            func(r *otp.CommandAttemptRecord) { r.Binding.TenantID = "other" },
		"target":            func(r *otp.CommandAttemptRecord) { r.Binding.RecordID = "other" },
		"subject":           func(r *otp.CommandAttemptRecord) { r.Binding.UserID = "other" },
		"correlation":       func(r *otp.CommandAttemptRecord) { r.Binding.CorrelationID = "other" },
		"policy":            func(r *otp.CommandAttemptRecord) { r.Binding.PolicyVersion++ },
		"operation":         func(r *otp.CommandAttemptRecord) { r.Operation.Owner = "identity/phone" },
		"invalid-operation": func(r *otp.CommandAttemptRecord) { r.Operation.SchemaVersion = 0 },
		"continuation":      func(r *otp.CommandAttemptRecord) { r.Attempt.Continuation = otp.Continuation{} },
		"signature":         func(r *otp.CommandAttemptRecord) { r.Signature[0] ^= 1 },
		"zero-signature":    func(r *otp.CommandAttemptRecord) { r.Signature = [32]byte{} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if i.VerifyCommandRecord(changed) == nil {
				t.Fatal("tampered record authenticated")
			}
			if _, err := i.RestoreForCommand(changed, code); err == nil {
				t.Fatal("tampered record restored")
			}
		})
	}
	other, _ := otp.NewAttemptIssuer(7, [32]byte{10})
	retired, _ := otp.NewAttemptIssuer(8, [32]byte{9})
	for _, issuer := range []otp.AttemptIssuer{{}, other, retired} {
		if issuer.VerifyCommandRecord(r) == nil {
			t.Fatal("retired/wrong/zero key authenticated")
		}
		if _, err := issuer.RestoreForCommand(r, code); err == nil {
			t.Fatal("wrong key restored")
		}
	}
	original, _ := i.RestoreForCommand(r, code)
	if _, err := (otp.AttemptIssuer{}).SealForCommand(original); err == nil {
		t.Fatal("zero issuer sealed original")
	}
	if _, err := i.RestoreForCommand(r, auth.OneTimeCode{}); err == nil {
		t.Fatal("zero code restored")
	}
	if _, err := i.SealForCommand(otp.AttemptCommand{}); err == nil {
		t.Fatal("zero attempt sealed")
	}
	legacy, _ := i.Prepare(context.Background(), r.Attempt.Continuation, otp.AttemptModeConsume, 11, code)
	if _, err := i.SealForCommand(legacy); err == nil {
		t.Fatal("legacy gained command custody")
	}
	a, _ := other.PrepareForCommand(context.Background(), r.Binding, r.Operation, r.Attempt.Continuation, otp.AttemptModeConsume, 11, code)
	if _, err := i.SealForCommand(a); err == nil {
		t.Fatal("foreign prepared attempt re-signed")
	}
	for _, value := range []any{r, otp.CommandAttemptRecord{}} {
		if _, err := json.Marshal(value); err == nil || !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("private record leaked")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil {
			t.Fatal("private record exported")
		}
	}
}

func FuzzCommandRecordRestore(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "correlation", uint8(2), uint64(11))
	f.Add("!", "!", "", uint8(0), uint64(0))
	f.Fuzz(func(t *testing.T, id, fingerprint, correlation string, mode uint8, version uint64) {
		i, r, code := commandRecordFixture(t)
		original := r
		r.Attempt.AttemptID = otp.AttemptID(id)
		r.Attempt.Fingerprint = otp.AttemptFingerprint(fingerprint)
		r.Binding.CorrelationID = correlation
		r.Attempt.Mode = otp.AttemptMode(mode)
		r.Attempt.ExpectedVersion = version
		// No forged projection may create a restored submission. The signature
		// remains from the original unpredictable server ID/fingerprint.
		if _, err := i.RestoreForCommand(r, code); err == nil && r != original {
			t.Fatal("changed private projection restored")
		}
	})
}

func TestRestoredCommandAttemptUsesOriginalCountedPolicy(t *testing.T) {
	i, r, code := commandRecordFixture(t)
	s, v, _ := challengeFixture(t)
	s.Version = 11
	challenge, err := otp.NewChallenge(s)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			restored, err := i.RestoreForCommand(r, code)
			if err != nil {
				t.Error(err)
				return
			}
			decision, err := v.EvaluateAttempt(challenge, restored, s.IssuedAt)
			if err != nil || decision.Outcome != otp.AttemptReserved || decision.UsedAttempts != 1 || decision.Version != 12 {
				t.Error("restored comparison lost original bounded policy", err)
			}
		})
	}
	wg.Wait()
	// A valid MAC cannot extend expiry or turn restored custody into a proof.
	a, _ := i.RestoreForCommand(r, code)
	d, err := v.EvaluateAttempt(challenge, a, s.ExpiresAt)
	if err != nil || d.Outcome != otp.AttemptExpired || d.UsedAttempts != 0 {
		t.Fatal("restoration renewed validity", err)
	}
	changed := r
	cb, _ := r.Attempt.Continuation.Bindings()
	cb.Scope.AuthorizationBinding = [32]byte{}
	cb.Scope.Generation++
	changed.Attempt.Continuation, err = otp.NewContinuation(cb.Scope, cb.Authorization, cb.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if i.VerifyCommandRecord(changed) == nil {
		t.Fatal("changed continuation authenticated")
	}
}
