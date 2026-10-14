package mfapostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"slices"
	"strconv"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func (p *totpURIPhase) loadOTPConfirmation(ctx context.Context) error {
	if p == nil || p.otpConfirmation == nil {
		return invalidEnrollment()
	}
	s, r := p.otpConfirmation, p.otpConfirmRequest
	var sendID, fingerprint, inputWire, outputWire, activationID []byte
	var keyVersion, state int64
	var row, before, generation string
	err := s.shared.enrollment.pool.Raw().QueryRow(ctx, `SELECT f.last_send_command_id,k.fingerprint,k.fingerprint_key_version,
CASE WHEN octet_length(k.request_preparation_ciphertext)<=$5 THEN k.request_preparation_ciphertext ELSE ''::bytea END,
CASE WHEN octet_length(c.preparation_ciphertext)<=$5 THEN c.preparation_ciphertext ELSE ''::bytea END,
c.preparation_ciphertext_generation::text,f.state,f.row_version::text,COALESCE(f.activation_before_version::text,''),f.activation_command_id
FROM identity_mfa.otp_factors f
JOIN identity.commands c ON c.tenant_id=f.tenant_id AND c.command_id=f.last_send_command_id AND c.purpose=f.last_send_purpose AND c.state='committed'
JOIN identity.request_key_mappings k ON k.tenant_id=c.tenant_id AND k.command_id=c.command_id AND k.namespace=$4 AND k.actor_kind='user' AND k.actor_id=f.user_id AND k.method='POST' AND k.route_id=c.purpose
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state IN(1,2)`, string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.FactorID), s.shared.enrollment.config.RequestKeys.Namespace, maximumEnrollmentCustody).Scan(&sendID, &fingerprint, &keyVersion, &inputWire, &outputWire, &generation, &state, &row, &before, &activationID)
	defer clear(inputWire)
	defer clear(outputWire)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ForbiddenError{}
		}
		return enrollmentReadError(ctx)
	}
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(sendID))
	gen, genErr := strconv.ParseUint(generation, 10, 64)
	if err != nil || genErr != nil || gen == 0 || strconv.FormatUint(gen, 10) != generation || len(fingerprint) != 32 || keyVersion < 1 || keyVersion > math.MaxUint32 || len(inputWire) == 0 || len(outputWire) == 0 || id == r.CommandID {
		return invalidEnrollment()
	}
	op := otpSendOperation()
	key := kernel.RequestKeyPreparationBinding{Namespace: s.shared.enrollment.config.RequestKeys.Namespace, Scope: kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: uint32(keyVersion)}, Feature: kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, PolicyVersion: s.shared.enrollment.config.RequestKeys.Policy.PolicyVersion, IntentDigest: [32]byte(fingerprint)}
	// Reconstruct only the actual recorded original root. No fabricated public
	// send request, idempotency key, fresh primary or new counter input is used.
	source := &totpURIPhase{state: s.sender.common, send: s.sender}
	aad, err := source.otpSendInputAAD(key)
	if err != nil {
		return err
	}
	codec := &totpEnrollmentPhase{state: s.shared.enrollment}
	plain, err := codec.open(ctx, aad, inputWire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input otpEnrollmentSendInput
	if decodeEnrollmentJSON(plain, &input) != nil {
		return invalidEnrollment()
	}
	retain := false
	defer func() {
		if !retain {
			clear(input.Parent.Primary)
			clear(input.NativeInput)
		}
	}()
	b, parent := input.Binding, input.Parent.Binding
	if input.Schema != 2 || input.Root == nil || input.Root.Binding != b || input.Root.Operation != op || b.ValidateFor(op) != nil || b.CommandID != id || b.TenantID != r.TenantID || b.UserID != identity.UserID(r.Caller.Request.Subject.ID) || b.ActorID != identity.ActorID(b.UserID) || b.ActorKind != authorization.SubjectUser || b.RecordID != string(r.FactorID) || b.CorrelationID != string(id) || input.Parent.Schema != 2 || input.Parent.OTP == nil || input.RowVersion == 0 || input.RowVersion >= math.MaxUint64-1 || len(input.NativeInput) == 0 || len(input.NativeInput) > 32768 || parent.ValidateFor(enrollmentOperation()) != nil || parent.TenantID != b.TenantID || parent.UserID != b.UserID || parent.ActorID != b.ActorID || parent.ActorKind != b.ActorKind || parent.RecordID != b.RecordID || parent.CommandID == id || parent.PolicyID != b.PolicyID || parent.PolicyVersion != b.PolicyVersion || parent.CorrelationID != string(parent.CommandID) || b.PolicyID != s.shared.enrollment.config.PolicyID || b.PolicyVersion != s.shared.enrollment.config.Coordinator.AdmissionPolicy.PolicyVersion {
		return invalidEnrollment()
	}
	m := input.Parent.OTP
	if !s.shared.enrollment.validEnrollmentMethod(input.Parent.Schema, input.Parent.Meta, m, &mfa.OTPEnrollmentSelection{Channel: m.Channel, IdentifierID: m.IdentifierID}) || m.FactorID != b.RecordID || m.AuthorityVersion >= math.MaxUint64-1 || input.IssuedAt.Before(m.CreatedAt) || !input.IssuedAt.Before(m.ExpiresAt) {
		return invalidEnrollment()
	}
	if _, err := NewPreparedOTPEnrollment(*m); err != nil || !input.Parent.Meta.ExpiresAt.Equal(input.Parent.Meta.CreatedAt.Add(s.shared.enrollment.config.TTL)) {
		return invalidEnrollment()
	}
	expected := input.RowVersion + 1
	if state == 1 && row != strconv.FormatUint(expected, 10) || state == 2 && (row != strconv.FormatUint(expected+1, 10) || before != strconv.FormatUint(expected, 10) || base64.RawURLEncoding.EncodeToString(activationID) != string(r.CommandID)) {
		return identity.ForbiddenError{}
	}
	root, err := identity.NewFeatureSessionCommand(*input.Root, r.Enrollment.Session)
	if err != nil {
		return invalidEnrollment()
	}
	source.command = root
	source.pending = &totpURIPending{Input: input.Parent, RowVersion: input.RowVersion, Wire: input.NativeInput, AuthorityVersion: m.AuthorityVersion + 1}
	aad, err = source.outputAAD(gen)
	if err != nil {
		return err
	}
	plainOutput, err := codec.open(ctx, aad, outputWire)
	if err != nil {
		return err
	}
	defer clear(plainOutput)
	var output totpURIOutput
	if decodeEnrollmentJSON(plainOutput, &output) != nil || output.Schema != 2 || output.Generation != gen || output.URI != "" || len(output.OTP) == 0 {
		return invalidEnrollment()
	}
	defer clear(output.OTP)
	p.nativeConfirmation, err = s.owner.RestoreEnrollmentConfirmation(ctx, root, input.NativeInput, gen, output.OTP)
	if err != nil || nilEnrollmentPrimary(p.nativeConfirmation) || p.nativeConfirmation.Contributor() != s.owner.ConfirmationContributor() {
		return invalidEnrollment()
	}
	p.primary, err = s.primary.RestoreEnrollmentForOTPConfirmation(ctx, r, parent.CommandID, expected, input.Parent.Primary)
	if err != nil {
		return err
	}
	p.pending = &totpURIPending{Input: input.Parent, RowVersion: expected, Wire: slices.Clone(input.NativeInput), AuthorityVersion: m.AuthorityVersion + 1}
	p.sendInput = &input
	retain = true
	return nil
}
