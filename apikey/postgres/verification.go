package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

var _ apikey.AtomicVerifier = (*Service)(nil)

func verificationOperation(unknown bool) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.verify", SchemaID: "apikey-verify-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if unknown {
		op.SchemaID, op.SubjectRequirement = "apikey-verify-unknown-v1", identity.FeatureSubjectAnonymousFlow
	}
	return op
}

// VerifyAndConsume authenticates one original modern, unlimited human-owned
// attempt through the native primary owners and sole identity coordinator.
// Required permissions intersect current policy; strict reduction is atomic
// even when use of a removed permission denies. No browser session is created.
// Preserve Fingerprint and Original for ambiguous outcome inquiry; retries
// cannot refresh a recorded positive result or repeat a permission transition.
func (s *Service) VerifyAndConsume(ctx context.Context, r apikey.AtomicVerificationRequest) (out apikey.AtomicVerificationResult, err error) {
	if s == nil || s.config == nil || ctx == nil || r.Validate(s.config().Configuration) != nil {
		return out, apikey.ErrInvalid
	}
	out = apikey.AtomicVerificationResult{AttemptID: r.AttemptID, State: apikey.VerificationAttemptNotDebited, Outcome: identity.CommitOutcomeNotCommitted}
	r.RequiredPermissions = slices.Clone(r.RequiredPermissions)
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out.Result = nil
			err = identity.UnavailableError{}
			if out.Fingerprint != ([32]byte{}) {
				out.Outcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: identity.CommandID(r.AttemptID)}
			}
		}
	}()
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().Profile.GlobalAuthorityID, TenantID: r.TenantID})
	if err != nil {
		return out, nativeError(ctx, err)
	}
	if !directory.Enabled {
		return out, apikey.ErrDenied
	}
	digest, err := r.Secret.Digest(s.config().Pepper, string(r.TenantID), s.config().Configuration)
	if err != nil {
		return out, err
	}
	record, err := s.verificationCandidate(ctx, r, digest)
	if err != nil {
		return out, err
	}
	if original, exists, err := s.retainedVerificationCandidate(ctx, r); err != nil {
		return out, err
	} else if exists {
		record = original
	}
	p := &verificationPhase{service: s, request: r, presented: digest, candidate: record}
	p.original, err = p.originalCommand()
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry, err = s.compose(p)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	if err := p.restoreOriginal(ctx); err != nil {
		return out, nativeError(ctx, err)
	}
	plan, err := p.plan()
	if err != nil {
		return out, nativeError(ctx, err)
	}
	result, fp, executionErr := p.coordinator.ExecutePreparedAPIKeyVerification(ctx, p.original, plan)
	out.Fingerprint = fp
	if fp != ([32]byte{}) {
		out.Original = p.query()
	}
	if result.Validate() != nil {
		return out, nativeError(ctx, executionErr)
	}
	out.Outcome = result.Outcome
	if result.Outcome == identity.CommitOutcomeInProgress {
		out.Outcome = identity.CommitOutcomeUnknown
		return out, identity.UnknownCommitError{CommandID: result.Binding.CommandID}
	}
	if result.Outcome != identity.CommitOutcomeCommitted {
		if executionErr == nil {
			executionErr = apikey.ErrDenied
		}
		return out, nativeError(ctx, executionErr)
	}
	return s.verificationEffect(ctx, out)
}

// ReconcileVerifyAndConsume asks only about the exact original submitted
// attempt. It carries no raw key, performs no comparison/debit, cannot create
// a missing command and never renews the original result's validity window.
// Current coordinator query policy authorizes disclosure. Expired committed
// success remains committed history but discloses no usable principal.
func (s *Service) ReconcileVerifyAndConsume(ctx context.Context, q apikey.VerificationReconcileQuery) (out apikey.AtomicVerificationResult, err error) {
	if s == nil || s.config == nil || ctx == nil || q.Validate() != nil {
		return out, apikey.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	p := &verificationPhase{service: s, binding: recoveryBinding(q.Original)}
	p.coordinator, p.registry, err = s.compose(p)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	kind, target := "identity.user", string(q.Original.UserID)
	if q.Original.AnonymousFlowID != "" {
		kind, target = "identity.anonymous-flow", q.Original.AnonymousFlowID
	}
	result, recoveryErr := p.coordinator.RecoverAPIKeyVerificationCommand(ctx, q.Original, q.Fingerprint, p.caller(kind, target))
	out = apikey.AtomicVerificationResult{AttemptID: q.AttemptID, Fingerprint: q.Fingerprint, Original: q.Original, State: apikey.VerificationAttemptNotDebited, Outcome: result.Outcome}
	if result.Validate() != nil {
		return apikey.AtomicVerificationResult{}, nativeError(ctx, recoveryErr)
	}
	if result.Outcome == identity.CommitOutcomeInProgress {
		out.Outcome = identity.CommitOutcomeUnknown
	}
	if result.Outcome != identity.CommitOutcomeCommitted {
		return out, nativeError(ctx, recoveryErr)
	}
	return s.verificationEffect(ctx, out)
}

func recoveryBinding(q identity.RecoveryQuery) identity.CommandBinding {
	op := verificationOperation(q.UserID == "")
	return identity.CommandBinding{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion}
}

func (s *Service) verificationCandidate(ctx context.Context, r apikey.AtomicVerificationRequest, digest apikey.Digest) (*apikey.Record, error) {
	query := `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND pepper_version=$3 AND lookup_digest=$4`
	args := []any{string(r.TenantID), r.ConfigurationID, int64(digest.PepperVersion), digest.Sum[:]}
	if r.Candidate != "" {
		query = `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`
		args = []any{string(r.TenantID), r.ConfigurationID, string(r.Candidate)}
	}
	var wire []byte
	err := s.pool.Raw().QueryRow(ctx, query, args...).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, nativeError(ctx, err)
	}
	record, err := decodeRecord(wire, s.config().Configuration)
	if err != nil || record.Owner.Spec().TenantID != r.TenantID || r.Candidate != "" && record.ID != r.Candidate {
		return nil, identity.UnavailableError{}
	}
	return &record, nil
}

// Committed routing survives a changed presented secret or absent current key.
// This projection is not authentication: the sole coordinator must still match
// the complete incoming intent before any original result is disclosed.
func (s *Service) retainedVerificationCandidate(ctx context.Context, r apikey.AtomicVerificationRequest) (*apikey.Record, bool, error) {
	var bound, wire []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT binding,record FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(r.AttemptID), string(r.TenantID)).Scan(&bound, &wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, nativeError(ctx, err)
	}
	var binding storedBinding
	if len(bound) > 4096 || decodeCanonical(bound, &binding) != nil {
		return nil, false, identity.UnavailableError{}
	}
	if binding.OperationID != "identity.apikey.verify" {
		// The global coordinator claim, not this projection, arbitrates a
		// cross-operation ID collision with the actual incoming command.
		return nil, false, nil
	}
	var effect verificationEffect
	if len(wire) > maximumCommandEffectBytes || decodeCanonical(wire, &effect) != nil || effect.Schema != 1 || effect.Snapshot.Binding != binding || binding.CommandID != identity.CommandID(r.AttemptID) || binding.TenantID != r.TenantID || binding.SchemaID != verificationOperation(binding.UserID == "").SchemaID {
		return nil, false, identity.UnavailableError{}
	}
	if binding.UserID == "" {
		if len(effect.Snapshot.Record) != 0 || binding.ActorKind != authorization.SubjectServiceAccount || binding.AnonymousFlowID != string(r.AttemptID) {
			return nil, false, identity.UnavailableError{}
		}
		return nil, true, nil
	}
	original, err := decodeRecord(effect.Snapshot.Record, s.config().Configuration)
	if err != nil || original.ID != apikey.KeyID(binding.ActorID) || original.Owner.Spec().TenantID != r.TenantID || original.Owner.Spec().UserID != binding.UserID || binding.ActorKind != authorization.SubjectAPIKey {
		return nil, false, identity.UnavailableError{}
	}
	return &original, true, nil
}

// Preparation survives protected-effect rollback, unlike command_effects.
// Read the existing coordinator's authorized custody, not a second journal or
// today's key version. This restores routing only: Execute must still match
// this request's complete original secret/permission fingerprint before any
// outcome or principal is disclosed.
func (p *verificationPhase) restoreOriginal(ctx context.Context) error {
	kind, target := "identity.user", string(p.binding.UserID)
	if p.binding.UserID == "" {
		kind, target = "identity.anonymous-flow", p.binding.AnonymousFlowID
	}
	q, caller := p.query(), p.caller(kind, target)
	observed, err := p.coordinator.ObserveCommandAdmission(ctx, q, caller)
	if observed.Validate() != nil {
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) {
			return err
		}
	}
	if observed.Absent {
		return nil
	}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: verificationOperation(p.binding.UserID == "")}
	wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, q, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return err
	}
	if err := p.restore(ctx, generation, wire); err != nil {
		return err
	}
	p.original, err = p.originalCommand()
	return err
}

func (p *verificationPhase) originalCommand() (identity.Command, error) {
	r, c := p.request, p.service.config()
	b := identity.CommandBinding{CommandID: identity.CommandID(r.AttemptID), TenantID: r.TenantID, ActorKind: authorization.SubjectServiceAccount, ActorID: identity.ActorID(c.Configuration.Spec().ID), AnonymousFlowID: string(r.AttemptID), OperationID: "identity.apikey.verify", SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: string(r.AttemptID)}
	if p.candidate != nil {
		b.UserID, b.ActorID, b.ActorKind, b.AnonymousFlowID = p.candidate.Owner.Spec().UserID, identity.ActorID(p.candidate.ID), authorization.SubjectAPIKey, ""
	}
	op := verificationOperation(p.candidate == nil)
	b.SchemaID = op.SchemaID
	p.binding = b
	wire, err := json.Marshal(struct {
		Configuration apikey.ConfigurationSpec
		Candidate     apikey.KeyID
		Pepper        uint32
		Digest        [32]byte
		Permissions   []string
		Debit         uint64
	}{c.Configuration.Spec(), r.Candidate, p.presented.PepperVersion, p.presented.Sum, slices.Clone(r.RequiredPermissions), r.DebitAmount})
	if err != nil {
		return identity.Command{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	version := uint64(0)
	if p.candidate != nil {
		version = p.candidate.Version
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "apikey.verify.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, {Name: "apikey.verify.key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}}}})
}

func (p *verificationPhase) query() identity.RecoveryQuery {
	b := p.binding
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
}

func (p *verificationPhase) caller(kind, id string) authorization.DecisionContext {
	b := p.binding
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.config().PolicyVersion), CorrelationID: string(b.CommandID), Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: authorization.ResourceType(kind), ID: authorization.ResourceID(id)}}}
}

func (p *verificationPhase) plan() (kernel.CommandPlan, error) {
	b := p.binding
	op := verificationOperation(b.UserID == "")
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "authentication_attempt", APIKeyVerification: &kernel.APIKeyVerificationPlan{}, Lifecycle: &kernel.LifecyclePlan{EventType: "api_key.permissions_changed.v1"}}
	target := string(b.AnonymousFlowID)
	events := []string{"identity.api_key.authenticate"}
	if p.candidate != nil {
		plan.SubjectType, target, plan.APIKeyVerification.KeyVersion = "api_key", string(b.ActorID), p.candidate.Version
		events = append(events, "identity.api_key.update")
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	for i, event := range events {
		actor := audit.ActorService
		seed, err := builder.Build(audit.RecordInput{OccurredAt: p.service.config().Clock.Now().UTC(), Action: event, Outcome: audit.OutcomeDenied, ReasonCode: "not_authorized", Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: plan.SubjectType, ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID, CausationID: string(b.CommandID)}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": plan.SubjectType, "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
		if err != nil {
			return kernel.CommandPlan{}, err
		}
		digest, err := kernel.FeatureAuditBindingDigest(b, op, plan.SubjectType, seed)
		if err != nil {
			return kernel.CommandPlan{}, err
		}
		plan.Audits = append(plan.Audits, kernel.AuditPlan{EventType: event, EventIndex: uint16(i), SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest})
	}
	return p.coordinator.PrepareFeaturePreparationPlan(p.original, plan)
}

func (s *Service) verificationEffect(ctx context.Context, out apikey.AtomicVerificationResult) (apikey.AtomicVerificationResult, error) {
	var binding, fingerprint, wire []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT binding,fingerprint,record FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(out.AttemptID), string(out.Original.TenantID)).Scan(&binding, &fingerprint, &wire)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	var retained storedBinding
	if decodeCanonical(binding, &retained) != nil || !hmac.Equal(fingerprint, out.Fingerprint[:]) {
		return out, identity.UnavailableError{}
	}
	b := identity.CommandBinding(retained)
	if (&verificationPhase{binding: b}).query() != out.Original {
		return out, identity.UnavailableError{}
	}
	var effect verificationEffect
	if len(wire) > maximumCommandEffectBytes || decodeCanonical(wire, &effect) != nil || effect.Schema != 1 || effect.Snapshot.Binding != retained {
		return out, identity.UnavailableError{}
	}
	if !effect.Authenticated {
		return out, apikey.ErrDenied
	}
	result, err := effect.result(s.config().Configuration)
	now, clockErr := s.primaryTime(ctx)
	if err != nil || clockErr != nil || result.ValidateAt(s.config().Configuration, now) != nil {
		return out, apikey.ErrDenied
	}
	out.State, out.Result = apikey.VerificationAttemptNotApplicable, &result
	return out, nil
}

// verificationEffect is an existing command_effects projection, not a second
// attempt state machine. Only the original coordinator transaction writes it.
type verificationEffect struct {
	Schema        uint16
	Authenticated bool
	Snapshot      verificationSnapshot
	Record        []byte
	Grant         []string
}

func (e verificationEffect) result(c apikey.Configuration) (apikey.VerificationResult, error) {
	r, err := decodeRecord(e.Record, c)
	if err != nil {
		return apikey.VerificationResult{}, err
	}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: r.Owner.Spec().TenantID, Kind: apikey.OwnerUser, UserID: r.Owner.Spec().UserID, Version: e.Snapshot.UserSecurity})
	if err != nil {
		return apikey.VerificationResult{}, err
	}
	return apikey.VerificationResult{Record: r, Owner: owner, Grant: slices.Clone(e.Grant), PolicyVersion: e.Snapshot.PolicyVersion, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: r.Owner.Spec().TenantID, ConfigurationID: c.Spec().ID, Version: e.Snapshot.ConfigurationVersion}, ReadStartedAt: e.Snapshot.Started, VerifiedAt: e.Snapshot.Verified, ValidUntil: e.Snapshot.Until}, nil
}

func sameRecord(a, b apikey.Record, c apikey.Configuration) bool {
	x, xe := encodeRecord(a, c)
	y, ye := encodeRecord(b, c)
	return xe == nil && ye == nil && bytes.Equal(x, y)
}
