package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// One private participant is registered once per synchronous Change invocation.
// Request and recovered input are frozen before execution, never shared with
// another request. Closures keep borrowed secret custody out of reflection.
type keyedPasswordChangePhase struct {
	service  *KeyedPasswordChangeService
	request  func() PasswordChangeRequest
	input    func() keyedPasswordChangeInput
	command  identity.Command
	plan     kernel.CommandPlan
	retained func() keyedPasswordChangeRetained
	arm      func(time.Time) error
}

type keyedPasswordChangeRetained struct {
	output     keyedPasswordChangeOutput
	command    identity.Command
	wireDigest [32]byte
	generation uint64
}

var _ kernel.RequestKeyPreparationContributor = (*keyedPasswordChangePhase)(nil)
var _ kernel.FeaturePreparationContributor = (*keyedPasswordChangePhase)(nil)
var _ kernel.CredentialReplacementContributor = (*keyedPasswordChangePhase)(nil)

func (*keyedPasswordChangePhase) Descriptor() kernel.ContributorDescriptor {
	return (&passwordChangePhase{}).Descriptor()
}
func (*keyedPasswordChangePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{replacementOperation()}
}

// Original preparation performs only bounded source reads, signed-proof
// validation and encryption. It does not compare/hash a password, collect HIBP,
// charge counters, mutate a proof, or authorize execution of the journal.
func (p *keyedPasswordChangePhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.inputAAD(k)
	if err != nil || p.request == nil {
		return nil, password.ErrPasswordWork
	}
	r := p.request()
	native := p.service.native
	original, err := native.source.lookup(ctx, r.TenantID, r.Session)
	if err != nil {
		return nil, err
	}
	spec, err := original.Bindings()
	if err != nil || k.Scope.ActorID != identity.ActorID(spec.UserID) || k.Scope.TenantID != spec.TenantID || spec.UserID != identity.UserID(r.Caller.Request.Subject.ID) {
		return nil, identity.ForbiddenError{}
	}
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: k.Scope.ActorID, ActorKind: k.Scope.ActorKind, OperationID: replacementOperation().OperationID, SchemaID: replacementOperation().SchemaID, SchemaVersion: replacementOperation().SchemaVersion, PolicyID: "identity-password", PolicyVersion: native.source.c.Coordinator.AdmissionPolicy.PolicyVersion, RecordID: spec.Authentication.CredentialID, CorrelationID: string(k.Admission.CommandID)}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: b.OperationID, Audience: native.c.Audience}
	if err := native.source.authorize(ctx, r.Caller, b, target); err != nil {
		return nil, err
	}
	use := p.service.proofUse(r, time.Time{})
	if use.SessionID != spec.SessionID || use.SessionVersion != spec.Version || native.validator.ValidateReauthenticationProof(ctx, r.Proof, use) != nil {
		return nil, identity.ForbiddenError{}
	}
	record, err := native.source.repository.Reauthentication(ctx, r.Proof.Proof.ID)
	if err != nil || record.Proof != r.Proof {
		return nil, identity.ForbiddenError{}
	}
	proof, err := encodeReauthenticationRecord(record)
	if err != nil {
		return nil, err
	}
	defer clear(proof)
	material, err := native.source.repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: b.TenantID, SubjectID: b.UserID})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		return nil, err
	}
	var primary time.Time
	if err := native.source.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&primary); err != nil {
		return nil, readerFailure(ctx)
	}
	inputFields, ok := intent.Fields()
	if !ok {
		return nil, password.ErrPasswordWork
	}
	input := keyedPasswordChangeInput{Schema: 1, Binding: b, Session: fields, Authority: material.Authority(), Hash: material.EncodedHash().String(), Proof: proof, OccurredAt: primary.UTC().Truncate(time.Microsecond), RequestInput: inputFields}
	if _, _, _, err := p.invocation(input, nil, identity.Command{}); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(input)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	defer clear(plain)
	return p.seal(ctx, aad, plain)
}

func (p *keyedPasswordChangePhase) originalCommand(c *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.Command, kernel.CommandPlan, error) {
	input := p.input()
	phase, original, _, err := p.invocation(input, nil, identity.Command{})
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	fields, err := kernel.CredentialReplacementFields(phase.intent)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	sessionFields, err := sessionpg.PasswordChangeSessionFields(original, p.service.native.c.SessionDisposition, p.service.native.c.MaximumSessions)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	intentBytes, err := json.Marshal(input.RequestInput)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(intentBytes)
	clear(intentBytes)
	fields = append(fields, sessionFields...)
	fields = append(fields, identity.FeatureField{Name: "keyed.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, identity.FeatureField{Name: "keyed.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: input.OccurredAt}})
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: input.Binding, Operation: replacementOperation(), Fields: fields})
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	r := p.request()
	spec, _ := original.Bindings()
	command, counters, err := p.service.native.c.Counters.PrepareCommandCounters(command, risk.Subject{User: string(input.Binding.UserID), Session: spec.SessionID, Network: r.Network}, input.OccurredAt)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.command = command
	plan, err := passwordChangePlan(c, registry, phase, input.Binding, command, counters, input.OccurredAt)
	return command, plan, err
}

func keyedPasswordMetadata(c identity.Command) (identity.FeatureCommandSpec, bool) {
	if s, ok := c.Feature(); ok {
		return s, true
	}
	return c.PasswordChangeFeature()
}

func (p *keyedPasswordChangePhase) CredentialReplacement(c identity.Command) (kernel.CredentialReplacementIntent, error) {
	if p == nil || p.input == nil {
		return kernel.CredentialReplacementIntent{}, password.ErrPasswordWork
	}
	want, ok := p.command.Feature()
	got, has := keyedPasswordMetadata(c)
	if !ok || !has || !reflect.DeepEqual(want, got) {
		return kernel.CredentialReplacementIntent{}, password.ErrPasswordWork
	}
	phase, _, _, err := p.invocation(p.input(), nil, c)
	if err != nil {
		return kernel.CredentialReplacementIntent{}, err
	}
	if _, generated := c.PasswordChangeFeature(); generated {
		hash, bearer, proof, custody := c.PasswordChangeCustody()
		r := p.request()
		if !custody || bearer.Token() != r.Session.Token() || proof != r.Proof {
			return kernel.CredentialReplacementIntent{}, password.ErrPasswordWork
		}
		fields, err := kernel.CredentialReplacementFields(phase.intent)
		if err != nil {
			return kernel.CredentialReplacementIntent{}, err
		}
		plain, err := identity.NewFeaturePasswordHashCommand(identity.FeatureCommandSpec{Binding: got.Binding, Operation: got.Operation, Fields: fields}, hash)
		if err != nil {
			return kernel.CredentialReplacementIntent{}, err
		}
		if _, _, err := passwordReplacement(plain, p.service.native.source.repository.policy); err != nil {
			return kernel.CredentialReplacementIntent{}, err
		}
	}
	return phase.intent, nil
}

func (p *keyedPasswordChangePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	i, err := p.CredentialReplacement(c)
	if err != nil || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != replacementOperation() || plan.SubjectType != "credential" || plan.CommandCounters == nil || plan.Capability != nil || plan.OTP != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "password.changed.v1" || plan.Lifecycle.BeforeVersion != i.Credential.Version || plan.Lifecycle.AfterVersion != i.Credential.Version+1 || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := plan.Audits[0]
	if a.EventType != replacementOperation().OperationID || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	return nil
}

func (p *keyedPasswordChangePhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if _, original := c.Feature(); !original {
		return password.ErrPasswordWork
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *keyedPasswordChangePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	phase, original, record, err := p.invocation(p.input(), nil, c)
	if err != nil {
		return err
	}
	spec, ok := c.Feature()
	b, _, _, err := w.FeatureScope(p)
	if err != nil || !ok || b != spec.Binding {
		return password.ErrPasswordWork
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.native.source.c.Profile, original, b)
	if err != nil || credential.Credential != phase.intent.Credential || credential.CredentialAuthorityVersion != phase.intent.ExpectedAuthorityVersion {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.native.source.c.Session, original); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	use := p.service.proofUse(p.request(), now)
	if err != nil || record.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	if p.arm == nil {
		return password.ErrPasswordWork
	}
	if err := p.arm(minPasswordChangeExpiry(record.Proof.Proof.ExpiresAt, record.Proof.Proof.IssuedAt.Add(p.service.native.c.MaximumAge))); err != nil {
		return err
	}
	return nil
}

type keyedPasswordChangeOutput struct {
	Schema uint8
	Hash   string
	Facts  []risk.Signal
}

func (p *keyedPasswordChangePhase) outputAAD(original identity.Command, generation uint64) (envelope.Context, error) {
	spec, ok := original.Feature()
	want, valid := p.command.Feature()
	if !ok || !valid || !reflect.DeepEqual(spec, want) || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Spec          identity.FeatureCommandSpec
		Generation    uint64
		Configuration [32]byte
	}{spec, generation, p.service.identity})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-password-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *keyedPasswordChangePhase) GenerateFeaturePreparation(ctx context.Context, original identity.Command, generation uint64) ([]byte, error) {
	// The gated native profile must use its original checked admission instead.
	return nil, password.ErrPasswordWork
}

func (p *keyedPasswordChangePhase) generateWithFacts(ctx context.Context, original identity.Command, generation uint64, originalFacts []risk.Signal) ([]byte, error) {
	aad, err := p.outputAAD(original, generation)
	if err != nil {
		return nil, err
	}
	input := p.input()
	r := p.request()
	until := minPasswordChangeExpiry(r.Proof.Proof.ExpiresAt, r.Proof.Proof.IssuedAt.Add(p.service.native.c.MaximumAge))
	remaining := until.Sub(p.service.native.source.c.Verifier.Now())
	if remaining <= 0 {
		return nil, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, remaining)
	defer stop()
	// Native primitive comparison observes the frozen predecessor hash, not a
	// newer material row. Current authority is checked again in final Work.
	var matched bool
	comparison, stopComparison := context.WithTimeout(ctx, p.service.native.source.c.Verifier.Timeout)
	err = r.Password.Use(func(raw []byte) error {
		if len(raw) < int(p.service.native.c.Screening.MinimumBytes) || len(raw) > int(p.service.native.c.Screening.MaximumBytes) {
			return password.ErrPasswordWork
		}
		result, e := p.service.native.source.c.Verifier.Primitive.Verify(comparison, raw, input.Hash)
		matched = result.Match()
		if errors.Is(e, primitive.ErrMismatch) {
			return nil
		}
		return e
	})
	comparisonErr := comparison.Err()
	stopComparison()
	if err != nil || comparisonErr != nil || matched {
		return nil, identity.ForbiddenError{}
	}
	facts := slices.Clone(originalFacts)
	screening := p.service.native.c.Screening
	screening.Collect = func(ctx context.Context, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		return slices.Clone(facts), ctx.Err()
	}
	preparer, err := password.NewHashPreparer(screening)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	hash, _, err := preparer.Prepare(ctx, r.Password, risk.Context{Tenant: string(input.Binding.TenantID), Operation: risk.Action(replacementOperation().OperationID), Attempt: string(input.Binding.CommandID)})
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(keyedPasswordChangeOutput{Schema: 1, Hash: hash.String(), Facts: facts})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	defer clear(plain)
	return p.seal(ctx, aad, plain)
}

func minPasswordChangeExpiry(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (p *keyedPasswordChangePhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	aad, err := p.outputAAD(original, generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plain, err := p.open(ctx, aad, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	defer clear(plain)
	var output keyedPasswordChangeOutput
	if decodeKeyedPasswordJSON(plain, &output) != nil || output.Schema != 1 || len(output.Facts) == 0 || len(output.Facts) > 32 {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	spec, _ := original.Feature()
	r := p.request()
	command, err := identity.NewFeaturePasswordChangeCommand(spec, output.Hash, r.Session, r.Proof)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	retained := keyedPasswordChangeRetained{output: output, command: command, wireDigest: sha256.Sum256(wire), generation: generation}
	p.retained = func() keyedPasswordChangeRetained { return retained }
	return command, p.plan, nil
}

func (p *keyedPasswordChangePhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	if p.retained == nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	retained := p.retained()
	if retained.generation != generation || retained.wireDigest != sha256.Sum256(wire) {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	// The original generated verifier is authenticated before any native write.
	wantHash, wantBearer, wantProof, valid := retained.command.PasswordChangeCustody()
	gotHash, gotBearer, gotProof, ok := command.PasswordChangeCustody()
	if !valid || !ok || wantHash != gotHash || wantBearer.Token() != gotBearer.Token() || wantProof != gotProof {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	phase, _, _, err := p.invocation(p.input(), slices.Clone(retained.output.Facts), command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	return phase.ApplyFeature(ctx, w, command)
}

func (p *keyedPasswordChangePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return (&passwordChangePhase{owner: p, service: p.service.native}).RecoverParticipant(ctx, w)
}
