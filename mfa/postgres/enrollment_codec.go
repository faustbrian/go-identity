package mfapostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/jackc/pgx/v5"
)

const maximumEnrollmentCustody = 131072

// These private records exist only inside the existing authenticated input and
// generated-output envelopes. No bearer is encoded. Output recovery plaintext
// is cleared when the synchronous invocation ends and is never a DB column.
type totpEnrollmentInput struct {
	Schema  uint32
	Binding identity.CommandBinding
	Meta    PendingTOTPMetadata
	Primary []byte
	Intent  []identity.FeatureField
	OTP     *PendingOTPMetadata `json:",omitempty"`
}

type otpEnrollmentSelection struct {
	Channel      delivery.Channel
	IdentifierID identity.IdentifierID
}
type enrollmentStoredRisk risk.PreparedProtectedProviderAdmission
type totpEnrollmentOutput struct {
	Schema, RecoveryKeyVersion uint32
	Generation                 uint64
	Meta                       PendingTOTPMetadata
	Envelope                   []byte
	Codes                      [][]byte
	Digests                    [][32]byte
	Risk                       enrollmentStoredRisk
	OTP                        *PendingOTPMetadata `json:",omitempty"`
}

func (p *totpEnrollmentPhase) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.state == nil || k.Namespace != p.state.config.RequestKeys.Namespace || k.Scope.RouteID != enrollmentOperation().OperationID || k.Scope.Method != "POST" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != enrollmentOperation() || k.PolicyVersion != p.state.config.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, invalidEnrollment()
	}
	frame, err := json.Marshal(struct {
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
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "mfa-enrollment-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *totpEnrollmentPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.input == nil || generation == 0 {
		return envelope.Context{}, invalidEnrollment()
	}
	frame, err := json.Marshal(struct {
		Input         totpEnrollmentInput
		Configuration [32]byte
		Generation    uint64
	}{*p.input, p.state.identity, generation})
	if err != nil {
		return envelope.Context{}, invalidEnrollment()
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "mfa-enrollment-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *totpEnrollmentPhase) seal(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	if ctx == nil || len(plain) == 0 || len(plain) > maximumEnrollmentCustody {
		return nil, invalidEnrollment()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sealed, err := p.state.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, Context: aad, KeyReference: p.state.config.ActiveEnvelopeKeyID})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumEnrollmentCustody {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	if err := ctx.Err(); err != nil {
		clear(wire)
		return nil, err
	}
	return wire, nil
}

func (p *totpEnrollmentPhase) open(ctx context.Context, aad envelope.Context, wire []byte) ([]byte, error) {
	if ctx == nil || len(wire) == 0 || len(wire) > maximumEnrollmentCustody {
		return nil, invalidEnrollment()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, invalidEnrollment()
	}
	plain, err := p.state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if cause := ctx.Err(); cause != nil {
		clear(plain)
		return nil, cause
	}
	if err != nil || len(plain) == 0 || len(plain) > maximumEnrollmentCustody {
		clear(plain)
		return nil, identity.UnavailableError{}
	}
	return plain, nil
}

func decodeEnrollmentJSON(plain []byte, target any) error {
	if len(plain) == 0 || len(plain) > maximumEnrollmentCustody {
		return invalidEnrollment()
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return invalidEnrollment()
	}
	canonical, err := json.Marshal(target)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return invalidEnrollment()
	}
	return nil
}

func (p *totpEnrollmentPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.inputAAD(k)
	if err != nil || p.request == nil {
		return nil, invalidEnrollment()
	}
	r := p.request()
	if k.Scope.TenantID != r.TenantID || k.Scope.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || k.Scope.ActorKind != authorization.SubjectUser {
		return nil, identity.ForbiddenError{}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	primary, err := p.state.config.Primary.PrepareEnrollment(ctx, r, k.Admission.CommandID, mfa.FactorID(id))
	if err != nil {
		return nil, err
	}
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	session, err := original.Bindings()
	if err != nil || session.TenantID != r.TenantID || session.UserID != identity.UserID(k.Scope.ActorID) {
		return nil, identity.ForbiddenError{}
	}
	snapshot, err := primary.Snapshot()
	if err != nil {
		return nil, err
	}
	defer clear(snapshot)
	var version string
	var active int32
	var at time.Time
	err = p.state.pool.Raw().QueryRow(ctx, `SELECT version::text,active_factors,clock_timestamp() FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(session.UserID)).Scan(&version, &active, &at)
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	authority, err := strconv.ParseUint(version, 10, 64)
	if err != nil || authority == 0 || authority == ^uint64(0) || active != 0 {
		return nil, identity.ForbiddenError{}
	}
	fields, ok := intent.Fields()
	if !ok {
		return nil, invalidEnrollment()
	}
	op := enrollmentOperation()
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: r.TenantID, UserID: session.UserID, ActorID: k.Scope.ActorID, ActorKind: k.Scope.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: p.state.config.PolicyID, PolicyVersion: p.state.config.Coordinator.AdmissionPolicy.PolicyVersion, RecordID: string(id), CorrelationID: string(k.Admission.CommandID)}
	input := totpEnrollmentInput{Schema: 1, Binding: b, Meta: PendingTOTPMetadata{TenantID: b.TenantID, UserID: b.UserID, FactorID: b.RecordID, AuthorityVersion: authority, Profile: p.state.config.Profile, CreatedAt: at.UTC(), ExpiresAt: at.UTC().Add(p.state.config.TTL)}, Primary: snapshot, Intent: fields}
	if p.state.method == "otp" {
		metadata, err := p.state.originalOTPRecipient(ctx, input.Meta, r.OTP)
		if err != nil {
			return nil, err
		}
		input.Schema, input.OTP = 2, &metadata
	}
	plain, err := json.Marshal(input)
	if err != nil {
		return nil, invalidEnrollment()
	}
	defer clear(plain)
	return p.seal(ctx, aad, plain)
}

func (p *totpEnrollmentPhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.inputAAD(k)
	if err != nil {
		return err
	}
	plain, err := p.open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input totpEnrollmentInput
	if err := decodeEnrollmentJSON(plain, &input); err != nil {
		clear(input.Primary)
		return err
	}
	r := p.request()
	intent, err := p.state.requestIntent(r)
	fields, ok := intent.Fields()
	op, b, m := enrollmentOperation(), input.Binding, input.Meta
	if err != nil || !ok || !reflect.DeepEqual(fields, input.Intent) || !p.state.validEnrollmentMethod(input.Schema, m, input.OTP, r.OTP) || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != authorization.SubjectUser || b.UserID != identity.UserID(k.Scope.ActorID) || b.OperationID != op.OperationID || b.SchemaID != op.SchemaID || b.SchemaVersion != op.SchemaVersion || b.PolicyID != p.state.config.PolicyID || b.PolicyVersion != p.state.config.Coordinator.AdmissionPolicy.PolicyVersion || b.CorrelationID != string(b.CommandID) || m.TenantID != b.TenantID || m.UserID != b.UserID || m.FactorID != b.RecordID || m.AuthorityVersion == 0 || m.AuthorityVersion == ^uint64(0) || m.Profile != p.state.config.Profile || m.CreatedAt.IsZero() || m.CreatedAt.Nanosecond()%1000 != 0 || !m.ExpiresAt.Equal(m.CreatedAt.Add(p.state.config.TTL)) {
		clear(input.Primary)
		return identity.ForbiddenError{}
	}
	primary, err := p.state.config.Primary.RestoreEnrollment(ctx, r, b.CommandID, mfa.FactorID(m.FactorID), input.Primary)
	if err != nil {
		clear(input.Primary)
		return err
	}
	p.input, p.primary = &input, primary
	return nil
}

func (s *totpEnrollmentState) validEnrollmentMethod(schema uint32, common PendingTOTPMetadata, otp *PendingOTPMetadata, selection *mfa.OTPEnrollmentSelection) bool {
	if s.method != "otp" {
		return schema == 1 && otp == nil && selection == nil
	}
	if schema != 2 || otp == nil || selection == nil || otp.Channel != selection.Channel || otp.IdentifierID != selection.IdentifierID ||
		otp.TenantID != common.TenantID || otp.UserID != common.UserID || otp.FactorID != common.FactorID || otp.AuthorityVersion != common.AuthorityVersion ||
		!otp.CreatedAt.Equal(common.CreatedAt) || !otp.ExpiresAt.Equal(common.ExpiresAt) || common.Profile != (mfa.TOTPProfile{}) {
		return false
	}
	_, err := NewPreparedOTPEnrollment(*otp)
	return err == nil
}

// Only the native directory supplies these original versions. This observation
// grants no persistence; protected admission locks/rechecks the exact row.
func (s *totpEnrollmentState) originalOTPRecipient(ctx context.Context, common PendingTOTPMetadata, selection *mfa.OTPEnrollmentSelection) (PendingOTPMetadata, error) {
	if selection == nil || selection.Validate() != nil {
		return PendingOTPMetadata{}, invalidEnrollment()
	}
	var kind, version, verification string
	var verified bool
	var state int16
	var at *time.Time
	err := s.pool.Raw().QueryRow(ctx, `SELECT kind,verified,verification_state,version::text,verification_version::text,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(common.TenantID), string(common.UserID), string(selection.IdentifierID)).Scan(&kind, &verified, &state, &version, &verification, &at)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PendingOTPMetadata{}, identity.ForbiddenError{}
		}
		return PendingOTPMetadata{}, enrollmentReadError(ctx)
	}
	if !verified || state != int16(identity.VerificationVerified) || at == nil || at.After(common.CreatedAt) || selection.Channel == delivery.ChannelEmail && kind != "email" || selection.Channel == delivery.ChannelSMS && kind != "phone" {
		return PendingOTPMetadata{}, identity.ForbiddenError{}
	}
	iv, e1 := strconv.ParseUint(version, 10, 64)
	vv, e2 := strconv.ParseUint(verification, 10, 64)
	if e1 != nil || e2 != nil {
		return PendingOTPMetadata{}, identity.UnavailableError{}
	}
	m := PendingOTPMetadata{TenantID: common.TenantID, UserID: common.UserID, FactorID: common.FactorID, AuthorityVersion: common.AuthorityVersion, CreatedAt: common.CreatedAt, ExpiresAt: common.ExpiresAt, IdentifierID: selection.IdentifierID, Channel: selection.Channel, IdentifierVersion: iv, VerificationVersion: vv}
	p, err := NewPreparedOTPEnrollment(m)
	if err != nil {
		return PendingOTPMetadata{}, err
	}
	return p.Metadata()
}

func enrollmentReadError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return identity.UnavailableError{}
}
