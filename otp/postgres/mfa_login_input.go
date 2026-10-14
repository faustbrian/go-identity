package postgres

import (
	"bytes"
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const mfaLoginPreparedInputPrefix = "identity-otp-mfa-login-prepared-input-v1\x00"

// PrepareLoginSend freezes the existing bounded code/bearer-free native record
// under this issuer's complete configuration identity. The MFA owner must
// authenticate child, browser, confirmed factor, recipient, primary and risk
// first and retain these bytes only inside its existing encrypted request-key
// preparation, never a transport DTO, another store or log. This method verifies
// original structural/cookie custody but grants no current admission or Allow.
// No generation, database IO, clock sampling or mutation occurs; errors return
// nil. Caller owns and should clear the returned transient bytes after use.
// ExpiresAt is an original child deadline: the retained challenge is capped to
// this issuer's shorter OTP TTL, without changing its original IssuedAt.
func (s *MFALoginIssuer) PrepareLoginSend(ctx context.Context, root identity.Command, input MFALoginSendInput) ([]byte, error) {
	if s == nil || s.store == nil || s.store.send == nil {
		return nil, ErrInvalidCommand
	}
	profile, _, err := s.store.send.policy.Bindings()
	if err != nil {
		return nil, ErrInvalidCommand
	}
	if until := input.IssuedAt.Add(profile.TTL); until.Before(input.ExpiresAt) {
		input.ExpiresAt = until
	}
	record, _, err := s.original(ctx, root, input, 1)
	if err != nil {
		return nil, err
	}
	spec, _ := root.Feature()
	wire, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	prepared := make([]byte, 0, len(mfaLoginPreparedInputPrefix)+32+len(wire))
	prepared = append(prepared, mfaLoginPreparedInputPrefix...)
	prepared = append(prepared, s.configuration[:]...)
	return append(prepared, wire...), nil
}

// ReadLoginSend strictly restores an original input after the MFA owner has
// authenticated its complete request-key envelope and unchanged request intent.
// Original recipient, browser, primary/child correlation and absolute times are
// retained; nothing is reread, generated, consumed or renewed. Wrong profile,
// configuration, command/browser, policy, malformed or oversized input denies.
// This is native preparation custody, not proof validation or live authority.
// The caller borrows immutable wire during this bounded, concurrent-safe call.
func (s *MFALoginIssuer) ReadLoginSend(ctx context.Context, root identity.Command, wire []byte) (MFALoginSendInput, error) {
	bad := func() (MFALoginSendInput, error) { return MFALoginSendInput{}, ErrInvalidCommand }
	if ctx == nil || s == nil || s.store == nil || s.store.send == nil || len(wire) <= len(mfaLoginPreparedInputPrefix)+32 || len(wire) > len(mfaLoginPreparedInputPrefix)+32+8192 || !bytes.HasPrefix(wire, []byte(mfaLoginPreparedInputPrefix)) {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return MFALoginSendInput{}, err
	}
	spec, ok := root.Feature()
	if !ok || spec.Operation != mfaLoginSendOperation() || !bytes.Equal(wire[len(mfaLoginPreparedInputPrefix):len(mfaLoginPreparedInputPrefix)+32], s.configuration[:]) {
		return bad()
	}
	record, err := decodeSendRequestRecord(wire[len(mfaLoginPreparedInputPrefix)+32:], spec.Binding)
	if err != nil || record.recipient == nil || !sameSendPolicy(record.policy, s.store.send.policy) {
		return bad()
	}
	input := MFALoginSendInput{Continuation: record.continuation, Authority: record.authority, Recipient: *record.recipient, IssuedAt: record.issuedAt, ExpiresAt: record.expiresAt}
	if _, _, err := s.original(ctx, root, input, 1); err != nil {
		return MFALoginSendInput{}, err
	}
	return input, nil
}

// GenerateLoginSend delegates acknowledged preparation to the existing OTP
// generator using only the retained original input. Invoke it only after the
// native coordinator records generation start and completes current admission.
// Never replace retained or ambiguous output. No persistence occurs here.
func (s *MFALoginIssuer) GenerateLoginSend(ctx context.Context, root identity.Command, inputWire []byte, generation uint64) ([]byte, error) {
	input, err := s.ReadLoginSend(ctx, root, inputWire)
	if err != nil {
		return nil, err
	}
	return s.Generate(ctx, root, input, generation)
}

// RestoreLoginSend restores the actual original encrypted OTP/delivery effect
// for the same root and acknowledged generation, without IO or regeneration.
// Persist still requires exact native MFA Work and all current authority fences.
func (s *MFALoginIssuer) RestoreLoginSend(ctx context.Context, root identity.Command, inputWire []byte, generation uint64, output []byte) (PreparedMFALoginSend, error) {
	input, err := s.ReadLoginSend(ctx, root, inputWire)
	if err != nil {
		return PreparedMFALoginSend{}, err
	}
	return s.Restore(ctx, root, input, generation, output)
}

// RecoverLoginSend contributes the existing native issuance tombstone vote
// without proof, browser restoration or generation. Retained issuance prevents
// a negative outcome; only the coordinator's original journal establishes the
// committed historical receipt. This method never redelivers or authenticates.
func (s *MFALoginIssuer) RecoverLoginSend(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if s == nil || s.store == nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	return (&issuanceContributor{store: s.store}).recoverIssuance(ctx, w, owner)
}
