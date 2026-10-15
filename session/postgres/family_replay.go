package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// FamilyReplayGuardConfig explicitly enables protective family revocation.
// LookupKeys are the same 1..4 retained core keys used for session validation.
// ActorID is a trusted configured service-account identity, never the token's
// human owner. Execution selects current policy and existing native composition.
// Dependencies are borrowed and must outlive calls; zero is invalid.
type FamilyReplayGuardConfig struct {
	Execution  IssueExecutorConfig
	LookupKeys []session.DigestKey
	ActorID    identity.ActorID
}

// FamilyReplayInput supplies a parsed opaque bearer, exact tenant and stable
// command identity. It selects no owner or family. HTTP must enforce origin/CSRF
// and selected transport policy before this explicit mutation, not during Get.
type FamilyReplayInput struct {
	TenantID      identity.TenantID
	Token         session.Token
	CommandID     identity.CommandID
	CorrelationID string
}

// FamilyReplayGuard detects retired bearer reuse and atomically revokes its
// exact family through the sole command owner. It authenticates no principal,
// issues no credential and owns no transaction, journal or goroutine. It is
// concurrency-safe; callers close the borrowed primary pool after calls finish.
type FamilyReplayGuard struct {
	owned *IssueExecutor
	keys  []session.DigestKey
	actor identity.ActorID
}

// NewFamilyReplayGuard freezes explicit composition without IO. Install all
// native rotation/family, kernel, audit and lifecycle migrations first. Core
// hashing validates retained keys; no application store or proof issuer is used.
func NewFamilyReplayGuard(pool *database.Pool, c FamilyReplayGuardConfig) (*FamilyReplayGuard, error) {
	if !scopeID(string(c.ActorID)) || len(c.LookupKeys) < 1 || len(c.LookupKeys) > 4 {
		return nil, session.ErrInvalidInput
	}
	probe, _ := session.ParseToken(strings.Repeat("A", 43))
	versions := make(map[uint32]bool, len(c.LookupKeys))
	for _, key := range c.LookupKeys {
		digest, err := probe.Digest(key, "configuration")
		if err != nil || versions[digest.KeyVersion] {
			return nil, session.ErrInvalidInput
		}
		versions[digest.KeyVersion] = true
	}
	owned, err := newOwnedSessionExecution(pool, c.Execution, false)
	if err != nil {
		return nil, err
	}
	return &FamilyReplayGuard{owned, append([]session.DigestKey(nil), c.LookupKeys...), identity.ActorID(strings.Clone(string(c.ActorID)))}, nil
}

// CheckReplay hashes only through the core token primitive and derives owner,
// family and original absolute expiry from primary retired lineage. A zero
// result with nil error means no eligible replay was observed; it is neither
// authentication nor proof of noncommit of a previously submitted command.
// Expired/absent/foreign tokens create no command. Retain a returned Binding for
// RecoverReplayCommand when acknowledgement is uncertain or the token expires.
//
// Eligible replay uses current service-actor policy and a full-intent command
// collision fence. Locked lineage, expiry, family CAS, protected audit and
// lifecycle commit together; retries reveal no token or renew any authority.
// Cancellation/panic after entry cannot prove rollback. Earlier caller deadlines
// win; synchronous detached kernel cleanup has its existing bounded budgets.
func (g *FamilyReplayGuard) CheckReplay(ctx context.Context, input FamilyReplayInput) (out identity.CommandResult, err error) {
	entered := false
	var binding identity.CommandBinding
	defer func() {
		if recover() != nil {
			err = session.ErrUnavailable
			if entered && out.Outcome != identity.CommitOutcomeCommitted {
				out = unknownFamilyReplay(binding)
				err = identity.UnknownCommitError{CommandID: binding.CommandID}
			}
		}
	}()
	if ctx == nil || g == nil || g.owned == nil || !scopeID(string(input.TenantID)) || !scopeID(input.CorrelationID) {
		return out, session.ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(input.CommandID)); err != nil {
		return out, session.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, g.owned.maximumDuration)
	defer stop()
	var proof replayEvidence
	found := false
	for _, key := range g.keys {
		digest, err := input.Token.Digest(key, string(input.TenantID))
		if err != nil {
			return out, session.ErrInvalidInput
		}
		candidate, exists, err := g.owned.native.readReplayEvidence(bounded, input.TenantID, digest)
		if err != nil {
			return out, err
		}
		if exists {
			if found {
				return out, session.ErrUnavailable
			}
			proof, found = candidate, true
		}
	}
	if !found {
		return out, nil
	}
	now := g.owned.clock.Now()
	if !sessionReadTime(now) {
		return out, session.ErrUnavailable
	}
	if !now.Before(proof.expires) {
		return out, nil
	}
	binding = identity.CommandBinding{CommandID: input.CommandID, TenantID: input.TenantID, UserID: proof.user, ActorID: g.actor, ActorKind: authorization.SubjectServiceAccount, OperationID: session.RevokeFamilyOperation().OperationID, RecordID: proof.family, PolicyID: g.owned.policyID, PolicyVersion: g.owned.policyVersion, SchemaID: session.RevokeFamilyOperation().SchemaID, SchemaVersion: 1, CorrelationID: input.CorrelationID}
	command, err := mapReplayEvidence(binding, proof)
	if err != nil {
		return out, err
	}
	plan, caller, err := g.prepareReplay(binding, command, proof.version)
	if err != nil {
		return out, err
	}
	if err = g.owned.allow(bounded, caller); err != nil {
		return out, err
	}
	// Bound reservation and final commit by original absolute validity using
	// primary time; policy/read latency cannot renew the source's deadline.
	bounded, stopExpiry, err := (&RevokeOneExecutor{owned: g.owned}).primaryDeadline(bounded, proof.expires)
	if err != nil {
		return out, err
	}
	defer stopExpiry()
	entered = true
	reservation, result, err := g.owned.coordinator.ReserveCommand(bounded, binding, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	work, err := g.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		return unknownFamilyReplay(binding), err
	}
	defer g.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := g.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		return g.owned.coordinator.Abort(work, err)
	}
	out, err = g.owned.coordinator.Commit(work, provisional)
	return out, err
}

func unknownFamilyReplay(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: session.RevokeFamilyOperation()}}
}

func (g *FamilyReplayGuard) prepareReplay(b identity.CommandBinding, command identity.Command, version uint64) (kernel.CommandPlan, authorization.DecisionContext, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, authorization.DecisionContext{}, session.ErrUnavailable
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: g.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session_family", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session_family", "aggregate.before_version": strconv.FormatUint(version, 10), "aggregate.after_version": strconv.FormatUint(version+1, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, authorization.DecisionContext{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, session.RevokeFamilyOperation(), "session_family", record)
	if err != nil {
		return kernel.CommandPlan{}, authorization.DecisionContext{}, err
	}
	declaration := kernel.CommandPlan{Contributors: g.owned.registry.Descriptors(), SubjectType: "session_family", Feature: &kernel.FeatureRegistration{Contributor: g.owned.native.Descriptor(), Operation: session.RevokeFamilyOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "session_family.revoked.v1", BeforeVersion: version, AfterVersion: version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: g.owned.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	plan, err := g.owned.coordinator.PrepareCommandPlan(b, command, declaration)
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(g.owned.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(g.actor), Kind: authorization.SubjectServiceAccount}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	return plan, caller, err
}

// RecoverReplayCommand returns historical family-revocation metadata under
// current trusted result-access policy without the original bearer. Supply every
// original safe scope field and an independently authenticated service caller.
// It never grants session authority, reserves missing commands or renews leases.
func (g *FamilyReplayGuard) RecoverReplayCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || g == nil || g.owned == nil {
		return identity.CommandResult{}, session.ErrInvalidInput
	}
	if q.OperationID != session.RevokeFamilyOperation().OperationID || q.ActorKind != authorization.SubjectServiceAccount || q.ActorID != g.actor || !scopeID(q.RecordID) || q.LinkMode != 0 {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	return g.owned.coordinator.RecoverFeatureCommand(ctx, q, caller)
}

// Format prevents diagnostic traversal of retained key and bearer custody.
func (FamilyReplayGuard) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.FamilyReplayGuard(redacted)"))
}

// Format redacts retained key and policy configuration.
func (FamilyReplayGuardConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.FamilyReplayGuardConfig(redacted)"))
}

// Format redacts bearer custody and input scope.
func (FamilyReplayInput) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.FamilyReplayInput(redacted)"))
}

// MarshalJSON denies implicit runtime or bearer configuration export.
func (FamilyReplayGuard) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalJSON denies implicit configuration export.
func (FamilyReplayGuardConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalJSON denies implicit bearer input export.
func (FamilyReplayInput) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
