package mfapostgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

func (p *otpActivePhase) sendInputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.state == nil || k.Namespace != p.state.shared.config.RequestKeys.Namespace || k.Scope.RouteID != otpActiveOperation(false).OperationID || k.Scope.Method != "POST" || k.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: otpActiveOperation(false)}) || k.PolicyVersion != p.state.shared.config.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	// Only the native authenticated codec may serialize this provenance.
	// The public binding intentionally rejects implicit diagnostic export.
	return otpActiveEnvelope("mfa-otp-active-send-input-v1", struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.state.identity})
}
func (p *otpActivePhase) binding(command identity.CommandID, verify bool) identity.CommandBinding {
	tenant, user, factor := p.sendRequest.TenantID, p.sendRequest.Caller.Request.Subject.ID, p.sendRequest.FactorID
	if verify {
		tenant, user, factor = p.verifyRequest.TenantID, p.verifyRequest.Caller.Request.Subject.ID, p.verifyRequest.FactorID
	}
	op := otpActiveOperation(verify)
	return identity.CommandBinding{CommandID: command, TenantID: tenant, UserID: identity.UserID(user), ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: string(factor), PolicyID: p.state.shared.config.PolicyID, PolicyVersion: p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(command)}
}
func (p *otpActivePhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	aad, err := p.sendInputAAD(k)
	if err != nil || p.verify || p.sendRequest.StepUp == nil {
		return nil, invalidAuthority()
	}
	r := p.sendRequest
	if k.Scope.TenantID != r.TenantID || k.Scope.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || k.Scope.ActorKind != authorization.SubjectUser {
		return nil, identity.ForbiddenError{}
	}
	primary, observed, err := p.state.config.Primary.PrepareOTPSend(ctx, r, k.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	active, err := p.state.reader.ReadForStepUp(ctx, observed, string(r.FactorID))
	if err != nil {
		return nil, err
	}
	meta, err := active.Metadata()
	if err != nil || meta.Factor.Channel != delivery.ChannelEmail || meta.Factor.RowVersion >= math.MaxUint64-1 {
		return nil, identity.ForbiddenError{}
	}
	recipient, err := active.Recipient()
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err := p.state.shared.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, enrollmentReadError(ctx)
	}
	now = now.UTC().Round(0)
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	life, err := original.Lifetime(now)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	expires := now.Add(p.state.config.TTL)
	if life.ExpiresAt.Before(expires) {
		expires = life.ExpiresAt
	}
	b := p.binding(k.Admission.CommandID, false)
	native, err := p.state.config.Issuance.PrepareStepUpSend(ctx, p.state.shared.pool, b, original, recipient, now, expires)
	if err != nil {
		return nil, err
	}
	defer clear(native)
	snapshot, err := primary.Snapshot()
	if err != nil {
		return nil, err
	}
	defer clear(snapshot)
	p.input = &otpActiveInput{Schema: 1, Binding: b, Factor: otpActiveFactor(meta.Factor), Primary: slices.Clone(snapshot), NativeInput: slices.Clone(native), SessionID: meta.SessionID, SessionVersion: meta.SessionVersion, CreatedAt: now, Until: meta.ValidUntil, ExpiresAt: expires, Action: string(r.StepUp.Purpose), Origin: r.Origin, Network: r.Network, Intent: k.IntentDigest}
	p.primary, p.until = primary, meta.ValidUntil
	if err := p.buildCommand(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(p.input)
	if err != nil {
		return nil, invalidAuthority()
	}
	defer clear(wire)
	return (&totpEnrollmentPhase{state: p.state.shared}).seal(ctx, aad, wire)
}

func (p *otpActivePhase) validInput(i otpActiveInput, verify bool) bool {
	b, m := i.Binding, i.Factor
	return i.Schema == 1 && b.ValidateFor(otpActiveOperation(verify)) == nil && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID) && b.RecordID == m.FactorID && b.TenantID == m.TenantID && b.UserID == m.UserID && b.PolicyID == p.state.shared.config.PolicyID && b.PolicyVersion == p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion && b.CorrelationID == string(b.CommandID) && p.state.allows(auth.Purpose(i.Action)) && slices.Contains(p.state.config.AllowedOrigins, i.Origin) && m.EnrollmentVersion > 0 && m.RowVersion > 0 && m.RowVersion < math.MaxUint64-1 && m.FactorAuthorityVersion > 0 && m.IdentifierID != "" && m.IdentifierVersion > 0 && m.VerificationVersion > 0 && m.Channel == delivery.ChannelEmail && m.ContinuationID == "" && m.ContinuationVersion == 0 && m.ScopeDigest == ([32]byte{}) && len(i.Primary) > 0 && len(i.Primary) <= 32768 && len(i.NativeInput) > 0 && len(i.NativeInput) <= 32768 && i.SessionID != "" && i.SessionVersion > 0 && !i.CreatedAt.IsZero() && i.CreatedAt.Nanosecond()%1000 == 0 && !i.Until.IsZero() && i.ExpiresAt.After(i.CreatedAt) && i.ExpiresAt.Sub(i.CreatedAt) <= p.state.config.TTL && i.Intent != ([32]byte{}) && (i.Root == nil || i.Root.Binding == b && i.Root.Operation == otpActiveOperation(verify))
}
func (p *otpActivePhase) restoreSend(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.sendInputAAD(k)
	if err != nil {
		return err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input otpActiveInput
	if decodeEnrollmentJSON(plain, &input) != nil || !p.validInput(input, false) || input.Root == nil || input.Binding != p.binding(k.Admission.CommandID, false) || !hmac.Equal(input.Intent[:], k.IntentDigest[:]) || input.Origin != p.sendRequest.Origin || input.Network != p.sendRequest.Network || input.Action != string(p.sendRequest.StepUp.Purpose) {
		clear(input.Primary)
		clear(input.NativeInput)
		return invalidAuthority()
	}
	primary, err := p.state.config.Primary.RestoreOTPSend(ctx, p.sendRequest, k.Admission.CommandID, input.Primary)
	if err != nil {
		clear(input.Primary)
		clear(input.NativeInput)
		return err
	}
	if err := p.matchPrimary(primary, input); err != nil {
		clear(input.Primary)
		clear(input.NativeInput)
		return err
	}
	p.input, p.primary, p.until = &input, primary, input.Until
	return nil
}
func (p *otpActivePhase) matchPrimary(primary OTPActivePrimary, input otpActiveInput) error {
	original, err := primary.Original()
	if err != nil {
		return err
	}
	s, err := original.Bindings()
	until, deadlineErr := primary.Deadline()
	if err != nil || deadlineErr != nil || s.TenantID != input.Binding.TenantID || s.UserID != input.Binding.UserID || s.SessionID != input.SessionID || s.Version != input.SessionVersion || !until.Equal(input.Until) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *otpActivePhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.state == nil || generation == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	var binding identity.CommandBinding
	var intent [32]byte
	if p.verify {
		if p.verifyRequest.StepUp == nil {
			return envelope.Context{}, invalidAuthority()
		}
		binding = p.binding(p.verifyRequest.CommandID, true)
		var err error
		intent, err = p.state.verifyIntent(p.verifyRequest)
		if err != nil {
			return envelope.Context{}, err
		}
	} else {
		if p.input == nil {
			return envelope.Context{}, invalidAuthority()
		}
		binding, intent = p.input.Binding, p.input.Intent
	}
	return otpActiveEnvelope("mfa-otp-active-output-v1", struct {
		Binding       identity.CommandBinding
		Verify        bool
		Generation    uint64
		Configuration [32]byte
		Intent        [32]byte
	}{binding, p.verify, generation, p.state.identity, intent})
}
func (p *otpActivePhase) openOutput(ctx context.Context, generation uint64, wire []byte) (otpActiveOutput, error) {
	aad, err := p.outputAAD(generation)
	if err != nil {
		return otpActiveOutput{}, err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, wire)
	if err != nil {
		return otpActiveOutput{}, err
	}
	defer clear(plain)
	var output otpActiveOutput
	if decodeEnrollmentJSON(plain, &output) != nil || output.Schema != 1 || output.Generation != generation || !p.validInput(output.Input, p.verify) || output.Input.Root == nil || len(output.Data) == 0 || len(output.Data) > maximumEnrollmentCustody {
		clear(output.Input.Primary)
		clear(output.Input.NativeInput)
		clear(output.Data)
		return otpActiveOutput{}, invalidAuthority()
	}
	return output, nil
}

func (p *otpActivePhase) loadVerification(ctx context.Context) error {
	r := p.verifyRequest
	if r.StepUp == nil {
		return invalidAuthority()
	}
	if err := authorizeNativeMFAAction(ctx, p.state.shared, r.Caller, authorization.Action(otpActiveOperation(true).OperationID)); err != nil {
		return err
	}
	if err := p.loadSource(ctx); err != nil {
		return err
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(r.CommandID))
	var exists bool
	if err := p.state.shared.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identity_command_id_claims WHERE command_id=$1)`, raw).Scan(&exists); err != nil {
		return enrollmentReadError(ctx)
	}
	if exists {
		b := p.binding(r.CommandID, true)
		q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, q, r.Caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: otpActiveOperation(true)}, p)
		if err != nil {
			return err
		}
		defer clear(wire)
		output, err := p.openOutput(ctx, generation, wire)
		if err != nil {
			return err
		}
		clear(output.Data)
		input := output.Input
		digest, err := p.state.verifyIntent(r)
		if err != nil || input.Binding != b || !hmac.Equal(input.Intent[:], digest[:]) || input.SessionID != p.source.SessionID || input.SessionVersion != p.source.SessionVersion || input.Origin != r.Origin || input.Network != r.Network || input.Action != string(r.StepUp.Purpose) {
			clear(input.Primary)
			clear(input.NativeInput)
			return invalidAuthority()
		}
		primary, err := p.state.config.Primary.RestoreOTPVerify(ctx, r, input.Primary)
		if err != nil {
			return err
		}
		if err := p.matchPrimary(primary, input); err != nil {
			return err
		}
		p.input, p.primary, p.until = &input, primary, input.Until
		return nil
	}
	primary, observed, err := p.state.config.Primary.PrepareOTPVerify(ctx, r)
	if err != nil {
		return err
	}
	snapshot, err := p.state.reader.ReadForStepUp(ctx, observed, string(r.FactorID))
	if err != nil {
		return err
	}
	meta, err := snapshot.Metadata()
	if err != nil || meta.SessionID != p.source.SessionID || meta.SessionVersion != p.source.SessionVersion || meta.Factor.EnrollmentVersion != p.source.Factor.EnrollmentVersion || meta.Factor.FactorAuthorityVersion != p.source.Factor.FactorAuthorityVersion || meta.Factor.RowVersion != p.source.Factor.RowVersion+1 || meta.Factor.IdentifierID != p.source.Factor.IdentifierID || meta.Factor.IdentifierVersion != p.source.Factor.IdentifierVersion || meta.Factor.VerificationVersion != p.source.Factor.VerificationVersion {
		return identity.ForbiddenError{}
	}
	var now time.Time
	if err := p.state.shared.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return enrollmentReadError(ctx)
	}
	now = now.UTC().Round(0)
	if !now.Before(p.source.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	wire, err := primary.Snapshot()
	if err != nil {
		return err
	}
	digest, err := p.state.verifyIntent(r)
	if err != nil {
		clear(wire)
		return err
	}
	p.input = &otpActiveInput{Schema: 1, Binding: p.binding(r.CommandID, true), Factor: otpActiveFactor(meta.Factor), Primary: wire, NativeInput: slices.Clone(p.source.NativeInput), SessionID: meta.SessionID, SessionVersion: meta.SessionVersion, CreatedAt: now, Until: meta.ValidUntil, ExpiresAt: p.source.ExpiresAt, Action: string(r.StepUp.Purpose), Origin: r.Origin, Network: r.Network, Intent: digest}
	p.primary, p.until = primary, meta.ValidUntil
	return nil
}

func (p *otpActivePhase) loadSource(ctx context.Context) error {
	r := p.verifyRequest
	id, _ := base64.RawURLEncoding.DecodeString(string(r.StepUp.SendCommandID))
	var fingerprint, inputWire, outputWire []byte
	var keyVersion int64
	var generation string
	err := p.state.shared.pool.Raw().QueryRow(ctx, `SELECT k.fingerprint,k.fingerprint_key_version,
CASE WHEN octet_length(k.request_preparation_ciphertext)<=$4 THEN k.request_preparation_ciphertext ELSE ''::bytea END,
CASE WHEN octet_length(c.preparation_ciphertext)<=$4 THEN c.preparation_ciphertext ELSE ''::bytea END,c.preparation_ciphertext_generation::text
FROM identity.request_key_mappings k
JOIN identity.commands c ON c.tenant_id=k.tenant_id AND c.command_id=k.command_id AND c.purpose=k.route_id AND c.state='committed'
WHERE k.tenant_id=$1 AND k.command_id=$2 AND k.namespace=$3 AND k.actor_kind='user' AND k.actor_id=$5 AND k.method='POST' AND k.route_id='identity.mfa.otp-send'`, string(r.TenantID), id, p.state.shared.config.RequestKeys.Namespace, maximumEnrollmentCustody, string(r.Caller.Request.Subject.ID)).Scan(&fingerprint, &keyVersion, &inputWire, &outputWire, &generation)
	defer clear(inputWire)
	defer clear(outputWire)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	if err != nil {
		return enrollmentReadError(ctx)
	}
	gen, err := strconv.ParseUint(generation, 10, 64)
	if err != nil || gen == 0 || strconv.FormatUint(gen, 10) != generation || keyVersion < 1 || keyVersion > math.MaxUint32 || len(fingerprint) != 32 || len(inputWire) == 0 || len(outputWire) == 0 {
		return invalidAuthority()
	}
	op := otpActiveOperation(false)
	k := kernel.RequestKeyPreparationBinding{Namespace: p.state.shared.config.RequestKeys.Namespace, Scope: kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: r.StepUp.SendCommandID, FingerprintKeyVersion: uint32(keyVersion)}, Feature: kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, PolicyVersion: p.state.shared.config.RequestKeys.Policy.PolicyVersion, IntentDigest: [32]byte(fingerprint)}
	aad, err := p.sendInputAAD(k)
	if err != nil {
		return err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, inputWire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input otpActiveInput
	if decodeEnrollmentJSON(plain, &input) != nil || !p.validInput(input, false) || input.Root == nil || input.Binding.CommandID != r.StepUp.SendCommandID || input.Binding.TenantID != r.TenantID || input.Binding.UserID != identity.UserID(r.Caller.Request.Subject.ID) || input.Binding.RecordID != string(r.FactorID) || input.Action != string(r.StepUp.Purpose) || !hmac.Equal(input.Intent[:], k.IntentDigest[:]) {
		clear(input.Primary)
		clear(input.NativeInput)
		return invalidAuthority()
	}
	source := &otpActivePhase{state: p.state, input: &input}
	output, err := source.openOutput(ctx, gen, outputWire)
	if err != nil {
		clear(input.Primary)
		clear(input.NativeInput)
		return err
	}
	defer clear(output.Data)
	defer clear(output.Input.Primary)
	defer clear(output.Input.NativeInput)
	if !reflect.DeepEqual(output.Input, input) {
		return invalidAuthority()
	}
	root, err := identity.NewFeatureSessionCommand(*input.Root, r.StepUp.Session)
	if err != nil {
		return err
	}
	verification, err := p.state.config.Issuance.RestoreStepUpVerification(ctx, root, input.NativeInput, gen, output.Data)
	if err != nil {
		return err
	}
	p.source, p.verification = &input, verification
	return nil
}
