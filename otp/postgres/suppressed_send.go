package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"reflect"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This record-free native variant conserves the original suppression decision.
// It is never an issuance command, even if a recipient appears during replay.
// The same canonical public route and sole coordinator own its terminal outcome.
func suppressedSendOperation(subject identity.FeatureSubjectRequirement) identity.FeatureOperation {
	op := issuanceOperation(subject)
	op.SchemaID += "-suppressed"
	op.RecordRequirement = identity.FeatureRecordOmitted
	return op
}

func isSuppressedSend(command identity.Command) bool {
	s, ok := command.Feature()
	return ok && s.Operation == suppressedSendOperation(s.Operation.SubjectRequirement)
}

func (p *authenticationSendContributor) mapSuppressedSend(ctx context.Context, input sendInitiationCustody, bearer auth.BearerCredential) (identity.Command, error) {
	if !input.suppressed || input.request.recipient != nil || input.original != (identity.Command{}) {
		return identity.Command{}, ErrInvalidCommand
	}
	original, err := p.store.mapPreparedSendRequest(ctx, input.request, input.binding, bearer)
	if err != nil {
		return identity.Command{}, err
	}
	wire, err := p.initiationReference(input)
	if err != nil {
		return identity.Command{}, err
	}
	defer clear(wire)
	spec, _ := original.Feature()
	spec.Operation = suppressedSendOperation(spec.Operation.SubjectRequirement)
	spec.Binding.RecordID = ""
	spec.Binding.SchemaID = spec.Operation.SchemaID
	spec.Fields = []identity.FeatureField{{Name: "otp.send-risk-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}}}
	return sendCommandWithBearer(spec, original)
}

func (p *authenticationSendContributor) suppressedInput(ctx context.Context, command identity.Command) (sendInitiationCustody, identity.Command, error) {
	bad := func(err error) (sendInitiationCustody, identity.Command, error) {
		return sendInitiationCustody{}, identity.Command{}, err
	}
	if ctx == nil || p == nil || p.store == nil || !isSuppressedSend(command) {
		return bad(ErrInvalidCommand)
	}
	spec, _ := command.Feature()
	if len(spec.Fields) != 1 || spec.Fields[0].Name != "otp.send-risk-input" || spec.Fields[0].Value.Kind != identity.FeatureBytes {
		return bad(ErrInvalidCommand)
	}
	input, err := p.restoreInitiationReference(ctx, command, spec.Fields[0].Value.Bytes)
	if err != nil {
		return bad(err)
	}
	if !input.suppressed || input.request.recipient != nil || input.original != (identity.Command{}) {
		return bad(ErrInvalidCommand)
	}
	expected := input.binding
	expected.RecordID, expected.SchemaID = "", spec.Operation.SchemaID
	if spec.Binding != expected {
		return bad(ErrInvalidCommand)
	}
	bearer, ok := command.SessionToken()
	if !ok {
		bearer, ok = command.PreAuthCookie()
	}
	if !ok {
		return bad(ErrInvalidCommand)
	}
	original, err := p.store.mapPreparedSendRequest(ctx, input.request, input.binding, bearer)
	if err != nil {
		return bad(err)
	}
	return input, original, nil
}

func suppressedSendAAD(command identity.Command, generation uint64) (envelope.Context, error) {
	spec, ok := command.Feature()
	if !ok || !isSuppressedSend(command) || generation == 0 || len(spec.Fields) != 1 || spec.Fields[0].Name != "otp.send-risk-input" || spec.Fields[0].Value.Kind != identity.FeatureBytes || len(spec.Fields[0].Value.Bytes) < 1 || len(spec.Fields[0].Value.Bytes) > 8192 {
		return envelope.Context{}, ErrInvalidCommand
	}
	wire := appendInitiationBinding([]byte("identity-otp-suppressed-output-v1\x00"), spec.Binding)
	wire = binary.BigEndian.AppendUint64(wire, generation)
	wire = append(wire, spec.Fields[0].Value.Bytes...)
	digest := sha256.Sum256(wire)
	clear(wire)
	return envelope.NewContext(map[string]string{"profile": "identity-otp-suppressed-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *authenticationSendContributor) suppressedSendPlan(command identity.Command) (kernel.CommandPlan, error) {
	return p.store.sendPlan(command, nil, true)
}

func (p *authenticationSendContributor) validateSuppressedSend(ctx context.Context, command identity.Command, plan kernel.CommandPlan) error {
	if _, _, err := p.suppressedInput(ctx, command); err != nil {
		return err
	}
	expected, err := p.suppressedSendPlan(command)
	plan.Digest = [32]byte{}
	if err != nil || !reflect.DeepEqual(plan, expected) {
		return ErrInvalidCommand
	}
	return nil
}

func (p *authenticationSendContributor) admitSuppressedSend(ctx context.Context, w kernel.Work, command identity.Command) error {
	_, original, err := p.suppressedInput(ctx, command)
	if err != nil {
		return err
	}
	r, flow, err := p.store.originalPreparedSend(ctx, original)
	if err != nil {
		return err
	}
	spec, _ := command.Feature()
	binding, registration, _, err := w.FeatureScope(p)
	if err != nil || binding != spec.Binding || registration.Operation != spec.Operation {
		return ErrInvalidCommand
	}
	return p.store.admitSendPrimary(ctx, w, r, flow, binding, p)
}

func (p *authenticationSendContributor) applySuppressedSend(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	a, inner, err := p.retained(ctx, command, generation, wire)
	defer clear(inner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	input, _, err := p.suppressedInput(ctx, command)
	if err != nil || a.dimensions != input.risk || !bytes.Equal(inner, []byte("IOAS1")) {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	if err := a.Check(ctx); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admitSuppressedSend(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// The exact same destination/purpose family is charged even when no
	// recipient exists. Skipping cooldown or maximum sends here would make a
	// fresh-key retry distinguish suppression from genuine issuance.
	continuation, err := input.request.continuation.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	// Match issuance's lock order: original primary/flow, shared abuse,
	// family, predecessors. Taking different subsets would expose populated
	// legacy state or allow reservation races to distinguish recipients.
	if err := p.store.lockout.initializeLockouts(ctx, query, w.Exec, p.store.schema, continuation.Scope); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, _, err := p.store.lockout.loadLockouts(ctx, query, p.store.schema, continuation.Scope); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.store.lockout.initializeSendFamily(ctx, query, w.Exec, p.store.schema, continuation.Scope); err != nil {
		return identity.FeatureReceipt{}, err
	}
	family, err := p.store.lockout.loadSendFamily(ctx, query, p.store.schema, continuation.Scope)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	// SQL locks preserve identity, not original freshness or flow expiry.
	if err := p.admitSuppressedSend(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	profile, _, err := input.request.policy.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	if _, err := admitSendPredecessors(ctx, query, family, continuation.Scope, profile, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admitSuppressedSend(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := persistSendWindow(ctx, w.Exec, family, mustIssueProfile(profile), now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admitSuppressedSend(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := a.Check(ctx); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	return identity.FeatureReceipt{Operation: spec.Operation}, nil
}
