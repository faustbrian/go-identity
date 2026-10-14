package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// Private until the public Send service supplies the complete native startup
// composition. Do not add these methods to Contributor: external admission is
// opt-in and must not change legacy registered participants dynamically.
type authenticationSendContributor struct {
	store         *Contributor
	evaluation    risk.Evaluator
	custody       risk.AuthenticationAdmissionCustody
	configuration string
}

func (*authenticationSendContributor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.authenticationSendContributor(redacted)"))
}
func (*authenticationSendContributor) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
func (*authenticationSendContributor) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

func newAuthenticationSendContributor(p *Contributor, c risk.AuthenticationAdmissionCustodyConfig) (*authenticationSendContributor, error) {
	if p == nil || p.send == nil || p.codec == nil {
		return nil, ErrInvalidConfiguration
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &authenticationSendContributor{store: p, evaluation: c.Evaluation, custody: custody, configuration: c.ConfigurationID}, nil
}

func (p *authenticationSendContributor) Descriptor() kernel.ContributorDescriptor {
	return (*Contributor)(nil).Descriptor()
}
func (p *authenticationSendContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{issuanceOperation(identity.FeatureSubjectUser), issuanceOperation(identity.FeatureSubjectAnonymousFlow), suppressedSendOperation(identity.FeatureSubjectUser), suppressedSendOperation(identity.FeatureSubjectAnonymousFlow)}
}

func sendCommandWithFields(original identity.Command, fields []identity.FeatureField) (identity.Command, error) {
	spec, ok := original.Feature()
	if !ok {
		return identity.Command{}, ErrInvalidCommand
	}
	spec.Fields = fields
	return sendCommandWithBearer(spec, original)
}

func (p *authenticationSendContributor) aad(original identity.Command, generation uint64, kind string) (envelope.Context, error) {
	base, err := preparedSendAAD(original, generation)
	if isSuppressedSend(original) {
		base, err = suppressedSendAAD(original, generation)
	}
	if err != nil {
		return envelope.Context{}, err
	}
	frame := appendAuthorityText([]byte("identity-otp-authentication-"+kind+"-v1\x00"), p.configuration)
	frame = appendAuthorityText(frame, string(base.AdditionalData()))
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-otp-authentication-" + kind + "-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *authenticationSendContributor) seal(ctx context.Context, original identity.Command, generation uint64, kind string, plain []byte) ([]byte, error) {
	aad, err := p.aad(original, generation, kind)
	if err != nil || len(plain) > maximumSendOutput-8192 {
		return nil, ErrInvalidCommand
	}
	sealed, err := p.store.codec.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.store.codec.current, Context: aad})
	if err != nil {
		return nil, custodyFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumSendOutput || ctx.Err() != nil {
		clear(wire)
		return nil, custodyFailure(ctx)
	}
	return wire, nil
}

func (p *authenticationSendContributor) open(ctx context.Context, original identity.Command, generation uint64, kind string, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximumSendOutput {
		return nil, ErrInvalidCommand
	}
	aad, err := p.aad(original, generation, kind)
	if err != nil {
		return nil, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, ErrInvalidCommand
	}
	plain, err := p.store.codec.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > maximumSendOutput || ctx.Err() != nil {
		clear(plain)
		return nil, custodyFailure(ctx)
	}
	return plain, nil
}

// Only authenticated, non-suppressed original initiation can select dimensions.
// The kernel fingerprint includes this encrypted input; no clearance flag or
// caller-selected decision is accepted, and encryption grants no authentication.
func (p *authenticationSendContributor) mapInitiatedSend(ctx context.Context, input sendInitiationCustody) (identity.Command, error) {
	if ctx == nil || p == nil || input.suppressed || !validInitiationRisk(input.risk) {
		return identity.Command{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	if _, _, err := p.store.originalPreparedSend(ctx, input.original); err != nil {
		return identity.Command{}, err
	}
	spec, _ := input.original.Feature()
	if input.binding != spec.Binding || input.attempt != string(spec.Binding.CommandID) {
		return identity.Command{}, ErrInvalidCommand
	}
	wire, err := p.initiationReference(input)
	if err != nil || len(wire) > 8192 {
		clear(wire)
		return identity.Command{}, ErrInvalidCommand
	}
	defer clear(wire)
	return sendCommandWithFields(input.original, append(spec.Fields, identity.FeatureField{Name: "otp.send-risk-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}}))
}

func (p *authenticationSendContributor) original(ctx context.Context, command identity.Command) (identity.Command, sendInitiationRisk, error) {
	if isSuppressedSend(command) {
		input, _, err := p.suppressedInput(ctx, command)
		if err != nil {
			return identity.Command{}, sendInitiationRisk{}, err
		}
		return command, input.risk, nil
	}
	bad := func() (identity.Command, sendInitiationRisk, error) {
		return identity.Command{}, sendInitiationRisk{}, ErrInvalidCommand
	}
	if p == nil || ctx == nil {
		return bad()
	}
	spec, ok := command.Feature()
	if !ok || len(spec.Fields) != 3 || spec.Fields[2].Name != "otp.send-risk-input" || spec.Fields[2].Value.Kind != identity.FeatureBytes {
		return bad()
	}
	base, err := sendCommandWithFields(command, spec.Fields[:2])
	if err != nil {
		return bad()
	}
	if _, _, err = p.store.originalPreparedSend(ctx, base); err != nil {
		return identity.Command{}, sendInitiationRisk{}, err
	}
	input, err := p.restoreInitiationReference(ctx, command, spec.Fields[2].Value.Bytes)
	if err != nil {
		return identity.Command{}, sendInitiationRisk{}, err
	}
	x, _ := base.Feature()
	y, _ := input.original.Feature()
	if input.suppressed || !reflect.DeepEqual(x, y) {
		return bad()
	}
	return base, input.risk, nil
}

// Native codec projection only: the kernel intentionally disallows exporting
// preparation provenance through ordinary JSON. This bounded frame retains
// that provenance with its already authenticated ciphertext, never encrypting
// it again or exposing original dimensions. Neither component grants authority.
type nativeSendPreparationBinding kernel.RequestKeyPreparationBinding

func (p *authenticationSendContributor) initiationReference(input sendInitiationCustody) ([]byte, error) {
	if len(input.retainedWire) == 0 || len(input.retainedWire) > 8192 {
		return nil, ErrInvalidCommand
	}
	meta, err := json.Marshal(nativeSendPreparationBinding(input.retainedBinding))
	if err != nil || len(meta) > 4096 {
		return nil, ErrInvalidCommand
	}
	wire := appendAuthorityText([]byte("IOAI2"), p.configuration)
	wire = appendAuthorityText(wire, string(meta))
	wire = appendAuthorityText(wire, string(input.retainedWire))
	if len(wire) > 8192 {
		clear(wire)
		return nil, ErrInvalidCommand
	}
	return wire, nil
}

func (p *authenticationSendContributor) restoreInitiationReference(ctx context.Context, command identity.Command, wire []byte) (sendInitiationCustody, error) {
	binding, sealed, err := decodeInitiationReference(wire, p.configuration)
	if err != nil {
		return sendInitiationCustody{}, err
	}
	bearer, ok := command.SessionToken()
	if !ok {
		bearer, ok = command.PreAuthCookie()
	}
	if !ok {
		return sendInitiationCustody{}, ErrInvalidCommand
	}
	return p.store.restoreSendInitiation(ctx, binding, sealed, bearer)
}

func decodeInitiationReference(wire []byte, expectedConfiguration string) (kernel.RequestKeyPreparationBinding, []byte, error) {
	bad := func() (kernel.RequestKeyPreparationBinding, []byte, error) {
		return kernel.RequestKeyPreparationBinding{}, nil, ErrInvalidCommand
	}
	if len(wire) > 8192 || !bytes.HasPrefix(wire, []byte("IOAI2")) {
		return bad()
	}
	r := recordReader{data: wire[5:], ok: true}
	configuration := r.text(256)
	meta := []byte(r.text(4096))
	sealed := []byte(r.text(8192))
	if !r.ok || len(r.data) != 0 || len(sealed) == 0 || configuration != expectedConfiguration {
		return bad()
	}
	var projection nativeSendPreparationBinding
	decoder := json.NewDecoder(bytes.NewReader(meta))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&projection) != nil {
		return bad()
	}
	canonical, err := json.Marshal(projection)
	if err != nil || !bytes.Equal(canonical, meta) {
		return bad()
	}
	return kernel.RequestKeyPreparationBinding(projection), sealed, nil
}

func sendRiskScope(command identity.Command) risk.Context {
	spec, _ := command.Feature()
	return risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Operation.OperationID), Attempt: string(spec.Binding.CommandID)}
}
func sendRiskSubject(d sendInitiationRisk) risk.Subject {
	return risk.Subject{Network: d.network, Device: d.device, IdentifierDigest: d.identifierDigest}
}

func (p *authenticationSendContributor) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if ctx == nil || p == nil {
		return nil, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	base, dims, err := p.original(ctx, command)
	if err != nil {
		return nil, err
	}
	spec, _ := base.Feature()
	kind := audit.ActorSystem
	if spec.Binding.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	scope, subject := sendRiskScope(base), sendRiskSubject(dims)
	result, err := p.evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Subject: subject, Phase: risk.NonIssuing, Attribution: &risk.DecisionAttribution{CommandID: spec.Binding.CommandID, CorrelationID: identity.CommandID(spec.Binding.CorrelationID), Actor: audit.ActorInput{Kind: kind, ID: string(spec.Binding.ActorID)}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: scope.Attempt}})
	if err != nil {
		return nil, err
	}
	admission, err := p.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, err
	}
	return &authenticationSendAdmission{owner: p, original: base, dimensions: dims, admission: admission, generates: true}, nil
}

type authenticationSendAdmission struct {
	owner      *authenticationSendContributor
	original   identity.Command
	dimensions sendInitiationRisk
	admission  risk.AuthenticationAdmission
	generates  bool
}

func (*authenticationSendAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.authenticationSendAdmission(redacted)"))
}
func (*authenticationSendAdmission) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
func (*authenticationSendAdmission) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

func (a *authenticationSendAdmission) Check(ctx context.Context) error { return a.admission.Check(ctx) }
func (a *authenticationSendAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if ctx == nil || !a.generates {
		return nil, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, a.owner.store.codec.maximumDuration)
	defer stop()
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	inner := []byte("IOAS1")
	var err error
	if !isSuppressedSend(a.original) {
		inner, err = a.owner.store.GenerateFeaturePreparation(ctx, a.original, generation)
	}
	if err != nil {
		return nil, err
	}
	defer clear(inner)
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	plain, err := encodeAuthenticationSend(a.dimensions, a.admission.Prepared(), inner)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return a.owner.seal(ctx, a.original, generation, "output", plain)
}

func (p *authenticationSendContributor) retained(ctx context.Context, original identity.Command, generation uint64, wire []byte) (*authenticationSendAdmission, []byte, error) {
	plain, err := p.open(ctx, original, generation, "output", wire)
	if err != nil {
		return nil, nil, err
	}
	defer clear(plain)
	dims, prepared, inner, err := decodeAuthenticationSend(plain)
	if err != nil {
		return nil, nil, err
	}
	admission, err := p.custody.Restore(ctx, prepared, sendRiskScope(original), sendRiskSubject(dims))
	if err != nil {
		clear(inner)
		return nil, nil, err
	}
	return &authenticationSendAdmission{owner: p, original: original, dimensions: dims, admission: admission}, inner, nil
}

func (p *authenticationSendContributor) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if ctx == nil || p == nil {
		return nil, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	base, dims, err := p.original(ctx, command)
	if err != nil {
		return nil, err
	}
	a, inner, err := p.retained(ctx, base, generation, wire)
	clear(inner)
	if err != nil {
		return nil, err
	}
	if a.dimensions != dims {
		return nil, ErrInvalidCommand
	}
	return a, nil
}

func (p *authenticationSendContributor) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	ctx, stop := context.WithTimeout(context.Background(), p.store.codec.maximumDuration)
	defer stop()
	if isSuppressedSend(command) {
		return p.validateSuppressedSend(ctx, command, plan)
	}
	base, _, err := p.original(ctx, command)
	if err != nil {
		return err
	}
	return p.store.ValidateFeaturePreparation(base, plan)
}
func (p *authenticationSendContributor) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	if isSuppressedSend(command) {
		return p.admitSuppressedSend(ctx, w, command)
	}
	base, _, err := p.original(ctx, command)
	if err != nil {
		return err
	}
	return p.store.admitFeaturePreparation(ctx, w, base, p)
}

// Generation is exclusively invocation-local admission's responsibility.
func (*authenticationSendContributor) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, ErrInvalidCommand
}
func (p *authenticationSendContributor) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if ctx == nil || p == nil {
		return identity.Command{}, kernel.CommandPlan{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	base, dims, err := p.original(ctx, command)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	a, inner, err := p.retained(ctx, base, generation, wire)
	defer clear(inner)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if a.dimensions != dims {
		return identity.Command{}, kernel.CommandPlan{}, ErrInvalidCommand
	}
	if isSuppressedSend(command) {
		if !bytes.Equal(inner, []byte("IOAS1")) {
			return identity.Command{}, kernel.CommandPlan{}, ErrInvalidCommand
		}
		plan, err := p.suppressedSendPlan(command)
		return command, plan, err
	}
	return p.store.RestoreFeaturePreparation(ctx, base, generation, inner)
}
func (p *authenticationSendContributor) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if isSuppressedSend(command) {
		ctx, stop := context.WithTimeout(context.Background(), p.store.codec.maximumDuration)
		defer stop()
		return p.validateSuppressedSend(ctx, command, plan)
	}
	return p.store.validatePreparedSendExecution(command, plan)
}
func (p *authenticationSendContributor) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if isSuppressedSend(command) {
		return p.applySuppressedSend(ctx, w, command)
	}
	original, err := p.store.originalFromGenerated(ctx, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	a, inner, err := p.retained(ctx, original, generation, wire)
	defer clear(inner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	phase, restored, err := p.store.restorePreparedSend(ctx, original, generation, inner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	x, _ := command.Feature()
	y, _ := restored.Feature()
	if !reflect.DeepEqual(x, y) {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	if err := a.Check(ctx); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Kernel checks the original admission again after all SQL waits and at
	// the final commit boundary; this owner introduces no second transaction.
	return phase.applyIssuance(ctx, w, restored, p)
}

var _ kernel.FeatureAdmissionPreparationContributor = (*authenticationSendContributor)(nil)

func (p *authenticationSendContributor) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	_, registration, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if registration.Operation == suppressedSendOperation(registration.Operation.SubjectRequirement) {
		return kernel.RecoveryNotCommitted, nil
	}
	return (&issuanceContributor{store: p.store}).recoverIssuance(ctx, w, p)
}

func (p *authenticationSendContributor) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	return p.store.PrepareRequestKey(ctx, b, intent)
}

func appendSendRisk(out []byte, d sendInitiationRisk) []byte {
	for _, s := range []string{d.network, d.device, d.identifierDigest} {
		out = appendAuthorityText(out, s)
	}
	return out
}
func readSendRisk(r *recordReader) sendInitiationRisk {
	return sendInitiationRisk{network: r.text(45), device: r.text(128), identifierDigest: r.text(64)}
}
func appendSendTime(out []byte, t time.Time) []byte {
	return appendAuthorityText(out, t.UTC().Format(time.RFC3339Nano))
}
func readSendTime(r *recordReader) time.Time {
	s := r.text(35)
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.UTC().Format(time.RFC3339Nano) != s {
		r.ok = false
	}
	return t
}

// Closed bounded native projection. Every risk MAC input is conserved; canonical
// UTC instants avoid location-dependent serialization and never renew facts.
func encodeAuthenticationSend(d sendInitiationRisk, p risk.PreparedAuthenticationAdmission, inner []byte) ([]byte, error) {
	if !validInitiationRisk(d) || len(p.Signals) < 1 || len(p.Signals) > 32 || len(inner) < 1 || len(inner) > maximumSendOutput-32768 {
		return nil, ErrInvalidCommand
	}
	out := appendSendRisk([]byte("IOAO1"), d)
	for _, s := range []string{p.Scope.Tenant, string(p.Scope.Operation), p.Scope.Attempt, p.CounterFingerprint} {
		if len(s) > 256 {
			return nil, ErrInvalidCommand
		}
		out = appendAuthorityText(out, s)
	}
	out = appendSendTime(out, p.Scope.Now)
	flag := byte(0)
	if p.Scope.IndependentFactor {
		flag = 1
	}
	out = append(out, flag)
	out = binary.BigEndian.AppendUint32(out, p.KeyVersion)
	out = binary.BigEndian.AppendUint64(out, p.PolicyVersion)
	for _, digest := range [][32]byte{p.ConfigurationDigest, p.ProofDigest, p.Signature} {
		out = append(out, digest[:]...)
	}
	out = append(out, byte(len(p.Signals)))
	for _, s := range p.Signals {
		for _, value := range []string{s.Tenant, string(s.Operation), s.Attempt, s.Name} {
			if len(value) > 256 {
				clear(out)
				return nil, ErrInvalidCommand
			}
			out = appendAuthorityText(out, value)
		}
		out = append(out, byte(s.State), byte(s.Trust))
		out = appendSendTime(out, s.ObservedAt)
		out = appendSendTime(out, s.ExpiresAt)
		out = binary.BigEndian.AppendUint64(out, uint64(s.RetryAfter))
		out = binary.BigEndian.AppendUint64(out, s.BreachCount)
		out = append(out, byte(s.Failure))
		out = appendSendTime(out, s.ProviderValidUntil)
		out = appendSendTime(out, s.CheckedAt)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(inner)))
	out = append(out, inner...)
	return out, nil
}
func decodeAuthenticationSend(plain []byte) (sendInitiationRisk, risk.PreparedAuthenticationAdmission, []byte, error) {
	bad := func() (sendInitiationRisk, risk.PreparedAuthenticationAdmission, []byte, error) {
		return sendInitiationRisk{}, risk.PreparedAuthenticationAdmission{}, nil, ErrInvalidCommand
	}
	if len(plain) > maximumSendOutput || !bytes.HasPrefix(plain, []byte("IOAO1")) {
		return bad()
	}
	r := recordReader{data: plain[5:], ok: true}
	d := readSendRisk(&r)
	p := risk.PreparedAuthenticationAdmission{Scope: risk.Context{Tenant: r.text(256), Operation: risk.Action(r.text(256)), Attempt: r.text(256)}, CounterFingerprint: r.text(256)}
	p.Scope.Now = readSendTime(&r)
	flag := r.u8()
	if flag > 1 {
		return bad()
	}
	p.Scope.IndependentFactor = flag == 1
	p.KeyVersion = r.u32()
	p.PolicyVersion = r.u64()
	copy(p.ConfigurationDigest[:], r.take(32))
	copy(p.ProofDigest[:], r.take(32))
	copy(p.Signature[:], r.take(32))
	n := int(r.u8())
	if n < 1 || n > 32 {
		return bad()
	}
	p.Signals = make([]risk.Signal, n)
	for i := range p.Signals {
		s := risk.Signal{Tenant: r.text(256), Operation: risk.Action(r.text(256)), Attempt: r.text(256), Name: r.text(256), State: risk.SignalState(r.u8()), Trust: risk.SignalTrust(r.u8())}
		s.ObservedAt = readSendTime(&r)
		s.ExpiresAt = readSendTime(&r)
		s.RetryAfter = time.Duration(r.u64())
		s.BreachCount = r.u64()
		s.Failure = risk.ProviderFailure(r.u8())
		s.ProviderValidUntil = readSendTime(&r)
		s.CheckedAt = readSendTime(&r)
		p.Signals[i] = s
	}
	size := r.u32()
	if size == 0 || size > maximumSendOutput-32768 {
		return bad()
	}
	inner := r.take(int(size))
	if !r.ok || len(r.data) != 0 || !validInitiationRisk(d) {
		return bad()
	}
	return d, p, bytes.Clone(inner), nil
}
