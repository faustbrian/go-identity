package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// PhonePasswordResetMetadataInput retains a bounded, immutable original encoding
// candidate, not recipient/factor custody or permission to execute recovery.
// The original encrypted SMS artifact must authenticate every field before any
// metadata is returned. Copies borrow no resource and are safe concurrently.
type PhonePasswordResetMetadataInput struct {
	read func() phonePasswordResetMetadataInput
}

type phonePasswordResetMetadataInput struct {
	originalFlow                       session.PreAuthTransaction
	recipient                          kernel.RecipientRecord
	authority                          AttemptAuthority
	factor                             mfapg.TOTPFactorMetadata
	factorEnvelope                     []byte
	issuedAt, expiresAt, smsObservedAt time.Time
}

// The existing original AAD grammar rejects larger complete frames. A single
// ciphertext larger than that cannot have belonged to an accepted frame; bound
// its owned copy before allocation without narrowing any original artifact.
const maximumPhoneResetOriginalFrame = 32768

func (i PhonePasswordResetMetadataInput) state() phonePasswordResetMetadataInput {
	if i.read == nil {
		return phonePasswordResetMetadataInput{}
	}
	return i.read()
}

// NewPhonePasswordResetMetadataInput copies original encrypted factor bytes and
// retained anonymous recipient/timeline metadata. It performs no IO or current
// admission. Only ReadOriginalMetadata can authenticate this candidate; no
// executable TOTP snapshot or send input can be obtained from it.
func NewPhonePasswordResetMetadataInput(flow session.PreAuthTransaction, recipient kernel.RecipientRecord, authority AttemptAuthority, factor mfapg.TOTPFactorMetadata, factorEnvelope []byte, issuedAt, requestedExpiresAt, smsObservedAt time.Time) (PhonePasswordResetMetadataInput, error) {
	if _, err := flow.Bindings(); err != nil || recipient.Query.UserID != "" || len(factorEnvelope) == 0 || len(factorEnvelope) > maximumPhoneResetOriginalFrame || !nativeTime(issuedAt) || !nativeTime(requestedExpiresAt) || !requestedExpiresAt.After(issuedAt) || !nativeTime(smsObservedAt) || smsObservedAt.Before(issuedAt) {
		return PhonePasswordResetMetadataInput{}, ErrInvalidCommand
	}
	i := phonePasswordResetMetadataInput{flow, recipient, authority, factor, bytes.Clone(factorEnvelope), issuedAt, requestedExpiresAt, smsObservedAt}
	return PhonePasswordResetMetadataInput{read: func() phonePasswordResetMetadataInput { return i }}, nil
}

func (PhonePasswordResetMetadataInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhonePasswordResetMetadataInput(redacted)"))
}
func (PhonePasswordResetMetadataInput) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
func (PhonePasswordResetMetadataInput) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// phoneResetOriginalAAD is the existing CaptureInput/Restore frame grammar.
// Sharing it keeps historical authentication byte-identical to executable
// original custody without making the historical candidate executable.
func phoneResetOriginalAAD(spec identity.FeatureCommandSpec, wire []byte, m mfapg.TOTPFactorMetadata, factorWire []byte, configuration [32]byte, generation uint64) (envelope.Context, error) {
	frame, err := json.Marshal(struct {
		Binding       identity.CommandBinding
		Operation     identity.FeatureOperation
		Fields        []identity.FeatureField
		Input         []byte
		Factor        mfapg.TOTPFactorMetadata
		Ciphertext    []byte
		Configuration [32]byte
		Generation    uint64
	}{spec.Binding, spec.Operation, spec.Fields, wire, m, factorWire, configuration, generation})
	if err != nil || len(frame) > maximumPhoneResetOriginalFrame {
		clear(frame)
		return envelope.Context{}, ErrInvalidCommand
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-otp-phone-reset-request-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
}

// ReadOriginalMetadata authenticates original browser possession and encrypted
// SMS issuance, returning only its actual ID and immutable issued interval.
// No current factor, credential, browser row or challenge row is read. Terminal
// own-consumption therefore does not erase historical budget addressing; this
// result grants no live recovery permission. Owners and command remain borrowed.
// Calls are bounded, concurrent-safe, zero-on-error and perform no generation,
// renewal, comparison, mutation, provider call or transaction.
func (s *PhonePasswordResetIssuer) ReadOriginalMetadata(ctx context.Context, root identity.Command, input PhonePasswordResetMetadataInput, generation uint64, output []byte) (id string, issuedAt, expiresAt time.Time, err error) {
	if ctx == nil {
		return "", time.Time{}, time.Time{}, ErrInvalidCommand
	}
	callerContext := ctx
	defer func() {
		if recover() != nil {
			err = ErrInvalidCommand
		}
		if callerContext.Err() != nil {
			err = callerContext.Err()
		}
		if err != nil {
			id = ""
			issuedAt = time.Time{}
			expiresAt = time.Time{}
		}
	}()
	p := s.state()
	if p == nil || generation == 0 {
		return "", time.Time{}, time.Time{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	i := input.state()
	spec, ok := root.Feature()
	m := i.factor
	if !ok || spec.Operation != phoneResetSendOperation() || spec.Binding.ValidateFor(spec.Operation) != nil || len(spec.Fields) > 124 || i.recipient.Query.UserID != "" || m.TenantID != spec.Binding.TenantID || m.UserID != spec.Binding.UserID || m.FactorID == "" || m.EnrollmentVersion == 0 || m.RowVersion == 0 || m.FactorAuthorityVersion == 0 || m.ContinuationID != "" || m.ContinuationVersion != 0 || m.ScopeDigest != ([32]byte{}) || m.Profile.Validate() != nil || len(i.factorEnvelope) == 0 || len(i.factorEnvelope) > maximumPhoneResetOriginalFrame || !nativeTime(i.issuedAt) || !nativeTime(i.expiresAt) || !i.expiresAt.After(i.issuedAt) || !nativeTime(i.smsObservedAt) || i.smsObservedAt.Before(i.issuedAt) {
		err = ErrInvalidCommand
		return
	}
	fields := []identity.FeatureField{{Name: "phone.reset.factor-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: m.FactorID}}, {Name: "phone.reset.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.EnrollmentVersion}}, {Name: "phone.reset.factor-authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.FactorAuthorityVersion}}}
	seen := 0
	for _, actual := range spec.Fields {
		if otpField(actual.Name) {
			err = ErrInvalidCommand
			return
		}
		if strings.HasPrefix(actual.Name, "phone.reset.factor-") {
			matched := false
			for _, expected := range fields {
				if reflect.DeepEqual(actual, expected) {
					matched = true
					seen++
					break
				}
			}
			if !matched {
				err = ErrInvalidCommand
				return
			}
		}
	}
	if seen != len(fields) {
		err = ErrInvalidCommand
		return
	}
	f, e := i.originalFlow.Bindings()
	if e != nil || i.originalFlow.Check(i.issuedAt, f.Binding, f.Cookie) != nil {
		err = ErrInvalidCommand
		return
	}
	until := i.expiresAt
	profile, _, _ := p.store.send.policy.Bindings()
	for _, cap := range []time.Time{i.issuedAt.Add(profile.TTL), f.Binding.ExpiresAt} {
		if cap.Before(until) {
			until = cap.UTC().Truncate(time.Microsecond)
		}
	}
	flow, e := otp.NewBoundPreAuthAuthorization(i.originalFlow)
	if e != nil {
		err = ErrInvalidCommand
		return
	}
	destination, e := otp.NewDestinationInput(i.recipient.Query.CanonicalValue)
	if e != nil {
		err = ErrInvalidCommand
		return
	}
	continuation, e := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(spec.Binding.TenantID), SubjectID: string(spec.Binding.UserID), Purpose: otp.PurposePasswordReset, Channel: otp.ChannelSMS, Destination: destination, ChallengeID: string(spec.Binding.CommandID), TargetID: string(i.authority.Credential.ID), PolicyVersion: spec.Binding.PolicyVersion, Generation: 1}, flow, session.RememberPolicy{})
	if e != nil {
		err = ErrInvalidCommand
		return
	}
	// Native CaptureInput uses the genuine known-user query and its original
	// SMS observation in appendSendRecipient. This private candidate verifies
	// that exact encoding through AEAD; it is never a live recipient authority.
	recipient := i.recipient
	recipient.Query.UserID = spec.Binding.UserID
	recipient.ObservedAt = i.smsObservedAt
	record := sendRequestRecord{continuation: continuation, policy: p.store.send.policy, authority: i.authority, recipient: &recipient, issuedAt: i.issuedAt, expiresAt: until}
	if _, err = p.store.authenticateSendFlow(ctx, root, continuation, i.authority); err != nil {
		return
	}
	wire, e := encodeSendRequestRecord(record, spec.Binding)
	if e != nil {
		err = e
		return
	}
	defer clear(wire)
	aad, e := phoneResetOriginalAAD(spec, wire, m, i.factorEnvelope, p.configuration, generation)
	if e != nil {
		err = e
		return
	}
	cookie, _ := root.PreAuthCookie()
	_, generated, e := restoreSendOutputContext(ctx, p.store, p.store.send.delivery, spec.Binding, generation, cookie, output, aad)
	if e != nil {
		err = e
		return
	}
	custody, _, e := p.store.authenticateIssuance(ctx, generated)
	if e != nil {
		err = e
		return
	}
	actual, e := custody.challenge.Bindings()
	if e != nil {
		err = e
		return
	}
	got, e := encodeSendRequestRecord(sendRequestRecord{continuation: actual.Continuation, policy: actual.Policy, authority: custody.authority, recipient: custody.recipient, issuedAt: actual.IssuedAt, expiresAt: actual.ExpiresAt}, spec.Binding)
	defer clear(got)
	if e != nil || !bytes.Equal(wire, got) {
		err = ErrInvalidCommand
		return
	}
	id = string(spec.Binding.CommandID)
	issuedAt = actual.IssuedAt
	expiresAt = actual.ExpiresAt
	return
}
