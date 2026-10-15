package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

// These records live only under the existing request-key envelope. NativeInput
// is OTP's exact code/bearer-free issuance record, not independent authority.
type otpEnrollmentSendInput struct {
	Schema          uint32
	Binding         identity.CommandBinding
	Parent          totpEnrollmentInput
	RowVersion      uint64
	IssuedAt        time.Time
	Origin, Network string
	NativeInput     []byte
	Root            *identity.FeatureCommandSpec
}

func (p *totpURIPhase) otpSendInputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.send == nil || k.Namespace != p.state.enrollment.config.RequestKeys.Namespace || k.Scope.RouteID != otpSendOperation().OperationID || k.Scope.Method != "POST" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != otpSendOperation() || k.PolicyVersion != p.state.enrollment.config.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, invalidEnrollment()
	}
	wire, err := json.Marshal(struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.state.identity})
	if err != nil {
		return envelope.Context{}, invalidEnrollment()
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "mfa-otp-send-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *totpURIPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	aad, err := p.otpSendInputAAD(k)
	if err != nil {
		return nil, err
	}
	r := p.sendRequest
	if k.Scope.TenantID != r.TenantID || k.Scope.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || k.Scope.ActorKind != authorization.SubjectUser {
		return nil, identity.ForbiddenError{}
	}
	p.request = mfa.TotpUriRequest{TenantID: r.TenantID, CommandID: k.Admission.CommandID, EnrollmentID: mfa.EnrollmentID(r.FactorID), Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}
	input, err := p.loadOTPSendParent(ctx, k)
	if err != nil {
		return nil, err
	}
	defer clear(input.Parent.Primary)
	defer clear(input.NativeInput)
	p.sendInput = &input
	p.pending = &totpURIPending{Input: input.Parent, RowVersion: input.RowVersion, Wire: slices.Clone(input.NativeInput), AuthorityVersion: input.Parent.OTP.AuthorityVersion + 1}
	if err = p.buildCommand(); err != nil {
		return nil, err
	}
	root, ok := p.command.Feature()
	if !ok {
		return nil, invalidEnrollment()
	}
	// Retain the actual complete static send root inside the existing request
	// envelope. Confirmation must authenticate its original output without
	// inventing an idempotency key, rebuilding counters or renewing the primary.
	input.Root = &root
	wire, err := json.Marshal(input)
	if err != nil {
		return nil, invalidEnrollment()
	}
	defer clear(wire)
	return (&totpEnrollmentPhase{state: p.state.enrollment}).seal(ctx, aad, wire)
}

func (p *totpURIPhase) loadOTPSendParent(ctx context.Context, k kernel.RequestKeyPreparationBinding) (otpEnrollmentSendInput, error) {
	bad := func(err error) (otpEnrollmentSendInput, error) { return otpEnrollmentSendInput{}, err }
	s, r := p.state.enrollment, p.sendRequest
	var parent, fingerprint, ciphertext []byte
	var keyVersion int64
	var rowVersion, identifier, identifierVersion, verificationVersion, channel string
	var at time.Time
	err := s.pool.Raw().QueryRow(ctx, `SELECT f.created_command_id,f.row_version::text,f.identifier_id,f.identifier_version::text,f.verification_version::text,f.channel,k.fingerprint,k.fingerprint_key_version,
CASE WHEN octet_length(k.request_preparation_ciphertext)<=$6 THEN k.request_preparation_ciphertext ELSE ''::bytea END,clock_timestamp()
FROM identity_mfa.otp_factors f JOIN identity.request_key_mappings k ON k.tenant_id=f.tenant_id AND k.command_id=f.created_command_id
JOIN identity.commands c ON c.tenant_id=f.tenant_id AND c.command_id=f.created_command_id AND c.purpose=f.created_purpose
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state=1 AND f.created_purpose=$5 AND c.state='committed'
AND k.namespace=$4 AND k.actor_kind='user' AND k.actor_id=f.user_id AND k.method='POST' AND k.route_id=f.created_purpose`, string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.FactorID), s.config.RequestKeys.Namespace, enrollmentOperation().OperationID, maximumEnrollmentCustody).Scan(&parent, &rowVersion, &identifier, &identifierVersion, &verificationVersion, &channel, &fingerprint, &keyVersion, &ciphertext, &at)
	defer clear(ciphertext)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return bad(identity.ForbiddenError{})
		}
		return bad(enrollmentReadError(ctx))
	}
	// Driver timezone representation is not a new observation. Canonicalize
	// the same original database instant before protected counter custody.
	at = at.UTC().Round(0)
	version, err := strconv.ParseUint(rowVersion, 10, 64)
	if err != nil || version == 0 || version == math.MaxUint64 || len(fingerprint) != 32 || keyVersion < 1 || keyVersion > math.MaxUint32 {
		return bad(invalidEnrollment())
	}
	parentID, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(parent))
	if err != nil {
		return bad(invalidEnrollment())
	}
	op := enrollmentOperation()
	parentKey := kernel.RequestKeyPreparationBinding{Namespace: s.config.RequestKeys.Namespace, Scope: kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: parentID, FingerprintKeyVersion: uint32(keyVersion)}, Feature: kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, PolicyVersion: s.config.RequestKeys.Policy.PolicyVersion, IntentDigest: [32]byte(fingerprint)}
	codec := &totpEnrollmentPhase{state: s}
	aad, err := codec.inputAAD(parentKey)
	if err != nil {
		return bad(err)
	}
	plain, err := codec.open(ctx, aad, ciphertext)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var original totpEnrollmentInput
	if decodeEnrollmentJSON(plain, &original) != nil {
		clear(original.Primary)
		return bad(invalidEnrollment())
	}
	retain := false
	defer func() {
		if !retain {
			clear(original.Primary)
		}
	}()
	if original.Schema != 2 || original.OTP == nil || original.Binding.CommandID != parentID || original.Binding.TenantID != r.TenantID || original.Binding.UserID != identity.UserID(r.Caller.Request.Subject.ID) || original.Binding.RecordID != string(r.FactorID) || original.OTP.FactorID != string(r.FactorID) || original.OTP.IdentifierID != identity.IdentifierID(identifier) || original.OTP.IdentifierVersion == 0 || strconv.FormatUint(original.OTP.IdentifierVersion, 10) != identifierVersion || strconv.FormatUint(original.OTP.VerificationVersion, 10) != verificationVersion || original.OTP.Channel != r.Channel || channel != otpChannelText(r.Channel) {
		return bad(identity.ForbiddenError{})
	}
	if !s.validEnrollmentMethod(original.Schema, original.Meta, original.OTP, &mfa.OTPEnrollmentSelection{Channel: r.Channel, IdentifierID: original.OTP.IdentifierID}) || original.Binding.ValidateFor(enrollmentOperation()) != nil || original.Binding.ActorID != identity.ActorID(original.Binding.UserID) || original.Binding.PolicyID != s.config.PolicyID || original.Binding.PolicyVersion != s.config.Coordinator.AdmissionPolicy.PolicyVersion || original.Binding.CorrelationID != string(parentID) || !original.Meta.ExpiresAt.Equal(original.Meta.CreatedAt.Add(s.config.TTL)) {
		return bad(invalidEnrollment())
	}
	if _, err := NewPreparedOTPEnrollment(*original.OTP); err != nil || original.OTP.AuthorityVersion == math.MaxUint64 || at.Before(original.OTP.CreatedAt) || !at.Before(original.OTP.ExpiresAt) {
		return bad(identity.ForbiddenError{})
	}
	primary, err := p.send.primary.RestoreEnrollmentForOTPSend(ctx, r, k.Admission.CommandID, parentID, version, original.Primary)
	if err != nil {
		return bad(err)
	}
	p.primary = primary
	session, err := primary.Original()
	if err != nil {
		return bad(err)
	}
	b := original.Binding
	b.CommandID, b.OperationID, b.SchemaID, b.SchemaVersion, b.CorrelationID = k.Admission.CommandID, otpSendOperation().OperationID, otpSendOperation().SchemaID, 1, string(k.Admission.CommandID)
	var destination string
	err = s.pool.Raw().QueryRow(ctx, `SELECT canonical_value FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND verified AND verification_state=2 AND version=$4::numeric AND verification_version=$5::numeric`, string(r.TenantID), string(b.UserID), identifier, identifierVersion, verificationVersion).Scan(&destination)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return bad(identity.ForbiddenError{})
		}
		return bad(enrollmentReadError(ctx))
	}
	repo, err := kernel.NewRepository(s.pool, kernel.Config{MaximumDuration: s.config.MaximumDuration})
	if err != nil {
		return bad(err)
	}
	kind := identity.IdentifierEmail
	if channel == "sms" {
		kind = identity.IdentifierPhone
	}
	recipient, err := repo.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, UserID: b.UserID, Kind: kind, CanonicalValue: destination, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return bad(err)
	}
	if recipient.Suppressed || recipient.Identifier.ID != original.OTP.IdentifierID || recipient.Identifier.Version != original.OTP.IdentifierVersion || recipient.Verification.Version != original.OTP.VerificationVersion {
		return bad(identity.ForbiddenError{})
	}
	native, err := p.send.issuance.PrepareEnrollmentSend(ctx, s.pool, b, session, recipient, at, original.OTP.ExpiresAt)
	if err != nil {
		return bad(err)
	}
	retain = true
	return otpEnrollmentSendInput{Schema: 2, Binding: b, Parent: original, RowVersion: version, IssuedAt: at, Origin: r.Origin, Network: r.Network, NativeInput: native}, nil
}

func (p *totpURIPhase) restoreOTPSendInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, ciphertext []byte) error {
	aad, err := p.otpSendInputAAD(k)
	if err != nil {
		return err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.enrollment}).open(ctx, aad, ciphertext)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input otpEnrollmentSendInput
	if decodeEnrollmentJSON(plain, &input) != nil {
		return invalidEnrollment()
	}
	retained := false
	defer func() {
		if !retained {
			clear(input.Parent.Primary)
			clear(input.NativeInput)
		}
	}()
	r := p.sendRequest
	b := input.Binding
	if input.Schema != 2 || input.Root == nil || input.Root.Binding != b || input.Root.Operation != otpSendOperation() || b.CommandID != k.Admission.CommandID || b.OperationID != otpSendOperation().OperationID || b.SchemaID != otpSendOperation().SchemaID || b.SchemaVersion != 1 || b.TenantID != r.TenantID || b.ActorKind != authorization.SubjectUser || b.UserID != identity.UserID(r.Caller.Request.Subject.ID) || b.ActorID != identity.ActorID(b.UserID) || b.RecordID != string(r.FactorID) || input.Parent.Schema != 2 || input.Parent.OTP == nil || input.Parent.OTP.FactorID != b.RecordID || input.Parent.OTP.Channel != r.Channel || input.Origin != r.Origin || input.Network != r.Network || input.RowVersion == 0 || input.RowVersion == math.MaxUint64 || len(input.NativeInput) == 0 || len(input.NativeInput) > 32768 || input.IssuedAt.Nanosecond()%1000 != 0 || input.IssuedAt.Before(input.Parent.OTP.CreatedAt) || !input.IssuedAt.Before(input.Parent.OTP.ExpiresAt) {
		return invalidEnrollment()
	}
	s := p.state.enrollment
	parent := input.Parent.Binding
	if b.ValidateFor(otpSendOperation()) != nil || b.PolicyID != s.config.PolicyID || b.PolicyVersion != s.config.Coordinator.AdmissionPolicy.PolicyVersion || b.CorrelationID != string(b.CommandID) || parent.ValidateFor(enrollmentOperation()) != nil || parent.TenantID != b.TenantID || parent.UserID != b.UserID || parent.ActorID != b.ActorID || parent.RecordID != b.RecordID || parent.CommandID == b.CommandID || parent.PolicyID != b.PolicyID || parent.PolicyVersion != b.PolicyVersion || parent.CorrelationID != string(parent.CommandID) || !s.validEnrollmentMethod(input.Parent.Schema, input.Parent.Meta, input.Parent.OTP, &mfa.OTPEnrollmentSelection{Channel: r.Channel, IdentifierID: input.Parent.OTP.IdentifierID}) || !input.Parent.Meta.ExpiresAt.Equal(input.Parent.Meta.CreatedAt.Add(s.config.TTL)) || input.IssuedAt.Location() != time.UTC {
		return invalidEnrollment()
	}
	if _, err := NewPreparedOTPEnrollment(*input.Parent.OTP); err != nil {
		return err
	}
	p.request = mfa.TotpUriRequest{TenantID: r.TenantID, CommandID: k.Admission.CommandID, EnrollmentID: mfa.EnrollmentID(r.FactorID), Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}
	p.primary, err = p.send.primary.RestoreEnrollmentForOTPSend(ctx, r, k.Admission.CommandID, input.Parent.Binding.CommandID, input.RowVersion, input.Parent.Primary)
	if err != nil {
		return err
	}
	p.pending = &totpURIPending{Input: input.Parent, RowVersion: input.RowVersion, Wire: slices.Clone(input.NativeInput), AuthorityVersion: input.Parent.OTP.AuthorityVersion + 1}
	p.sendInput = &input
	retained = true
	return nil
}

func otpChannelText(c delivery.Channel) string {
	if c == delivery.ChannelSMS {
		return "sms"
	}
	if c == delivery.ChannelEmail {
		return "email"
	}
	return ""
}
