package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strconv"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const maximumSendOutput = 1 << 20

// The original journal retains this encrypted output, not a new workflow row.
// This closed profile binds code-free challenge custody and original encrypted
// delivery together. Opening never remaps/re-encrypts either component, borrows
// the submitted bearer anew, and grants no current primary admission.
func sendOutputAAD(spec identity.FeatureCommandSpec, generation uint64) (envelope.Context, error) {
	op, err := boundIssuanceOperation(spec.Binding)
	if generation == 0 || err != nil || spec.Operation != op {
		return envelope.Context{}, ErrInvalidCommand
	}
	aad, err := commandCustodyAAD(spec, 1, "identity-otp-send-output-scope-v1\x00", "identity-otp-send-output-v1")
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(aad.AdditionalData())
	return envelope.NewContext(map[string]string{"profile": "identity-otp-send-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
}

func (p *issuanceContributor) sealSendOutput(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	spec, _ := command.Feature()
	aad, err := sendOutputAAD(spec, generation)
	if err != nil {
		return nil, err
	}
	return p.sealSendOutputContext(ctx, command, generation, aad)
}

func (p *issuanceContributor) sealSendOutputContext(ctx context.Context, command identity.Command, generation uint64, aad envelope.Context) ([]byte, error) {
	if ctx == nil || p == nil || p.store == nil || p.store.codec == nil || p.delivery == nil {
		return nil, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	custody, _, err := p.store.authenticateIssuance(ctx, command)
	if err != nil {
		return nil, err
	}
	spec, _ := command.Feature()
	if len(spec.Fields) != 2 {
		return nil, ErrInvalidCommand
	}
	if err := p.validateSendOutput(command); err != nil {
		return nil, err
	}
	var issue []byte
	for _, field := range spec.Fields {
		if field.Name == "otp.issue-custody" {
			issue = field.Value.Bytes
		}
	}
	if len(issue) < 1 || len(issue) > 8192 {
		return nil, ErrInvalidCommand
	}
	delivery, err := p.delivery.CheckpointPreparation(ctx, p.prepared, generation)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrInvalidCommand
	}
	s, _ := custody.challenge.Bindings()
	plain := binary.BigEndian.AppendUint32([]byte("IDOS1"), s.Digest.KeyVersion)
	variant := byte(1)
	if _, sessionBound := command.SessionToken(); sessionBound {
		variant = 2
	}
	plain = append(plain, variant)
	plain = binary.BigEndian.AppendUint32(plain, uint32(len(issue)))
	plain = append(plain, issue...)
	plain = binary.BigEndian.AppendUint32(plain, uint32(len(delivery)))
	plain = append(plain, delivery...)
	defer clear(plain)
	if len(plain) > maximumSendOutput-8192 {
		return nil, ErrInvalidCommand
	}
	sealed, err := p.store.codec.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.store.codec.current, Context: aad})
	if err != nil {
		return nil, custodyFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumSendOutput {
		return nil, custodyFailure(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return wire, nil
}

func restoreSendOutput(ctx context.Context, store *Contributor, delivery *deliverypg.Contributor, binding identity.CommandBinding, generation uint64, bearer auth.BearerCredential, wire []byte) (*issuanceContributor, identity.Command, error) {
	subject := identity.FeatureSubjectUser
	if binding.UserID == "" {
		subject = identity.FeatureSubjectAnonymousFlow
	}
	aad, err := sendOutputAAD(identity.FeatureCommandSpec{Binding: binding, Operation: issuanceOperation(subject)}, generation)
	if err != nil {
		return nil, identity.Command{}, ErrInvalidCommand
	}
	return restoreSendOutputContext(ctx, store, delivery, binding, generation, bearer, wire, aad)
}

func restoreSendOutputContext(ctx context.Context, store *Contributor, delivery *deliverypg.Contributor, binding identity.CommandBinding, generation uint64, bearer auth.BearerCredential, wire []byte, aad envelope.Context) (*issuanceContributor, identity.Command, error) {
	bad := func(err error) (*issuanceContributor, identity.Command, error) { return nil, identity.Command{}, err }
	if ctx == nil || store == nil || store.codec == nil || delivery == nil || len(wire) < 1 || len(wire) > maximumSendOutput {
		return bad(ErrInvalidCommand)
	}
	w, stop := context.WithTimeout(ctx, store.codec.maximumDuration)
	defer stop()
	if err := w.Err(); err != nil {
		return bad(err)
	}
	op, err := boundIssuanceOperation(binding)
	if err != nil {
		return bad(err)
	}
	spec := identity.FeatureCommandSpec{Binding: binding, Operation: op}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	plain, err := store.codec.crypto.Decrypt(w, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		return bad(custodyFailure(w))
	}
	if len(plain) < 18 || len(plain) > maximumSendOutput || string(plain[:5]) != "IDOS1" {
		return bad(ErrInvalidCommand)
	}
	version := binary.BigEndian.Uint32(plain[5:9])
	variant := plain[9]
	issue, rest, ok := sendOutputField(plain[10:], 8192)
	if !ok {
		return bad(ErrInvalidCommand)
	}
	deliveryWire, rest, ok := sendOutputField(rest, maximumSendOutput)
	if !ok || len(rest) != 0 || version == 0 {
		return bad(ErrInvalidCommand)
	}
	spec.Fields = []identity.FeatureField{{Name: "otp.issue-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: issue}}, {Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(version)}}}
	var command identity.Command
	switch variant {
	case 1:
		command, err = identity.NewFeaturePreAuthCommand(spec, bearer)
	case 2:
		command, err = identity.NewFeatureSessionCommand(spec, bearer)
	default:
		return bad(ErrInvalidCommand)
	}
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if _, _, err := store.authenticateIssuance(w, command); err != nil {
		return bad(err)
	}
	prepared, err := delivery.RestorePreparation(w, binding, generation, deliveryWire)
	if err != nil {
		return bad(custodyFailure(w))
	}
	phase, err := newIssuanceContributor(store, delivery, prepared)
	if err != nil {
		return bad(err)
	}
	if err := phase.validateSendOutput(command); err != nil {
		return bad(err)
	}
	if err := w.Err(); err != nil {
		return bad(err)
	}
	return phase, command, nil
}

func (p *issuanceContributor) validateSendOutput(command identity.Command) error {
	spec, ok := command.Feature()
	if !ok {
		return ErrInvalidCommand
	}
	if spec.Operation == mfaEnrollmentSendOperation() || spec.Operation == mfaLoginSendOperation() || spec.Operation == phoneEnrollmentSendOperation() {
		return p.validateIssuanceDelivery(command)
	}
	delivery, err := p.prepared.Plan()
	if err != nil {
		return ErrInvalidCommand
	}
	return p.ValidateFeatureCommand(command, kernel.CommandPlan{SubjectType: "otp_challenge", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "otp.send"}}, Delivery: &delivery})
}

func sendOutputField(wire []byte, limit int) ([]byte, []byte, bool) {
	if len(wire) < 4 {
		return nil, nil, false
	}
	n := uint64(binary.BigEndian.Uint32(wire[:4]))
	if n == 0 || n > uint64(limit) || n > uint64(len(wire)-4) {
		return nil, nil, false
	}
	return wire[4 : 4+int(n)], wire[4+int(n):], true
}
