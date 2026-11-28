package postgres

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// An invocation-private registration carries the opaque actor and exact target
// into Work without putting a synchronizer or bearer into the durable intent.
// Recovery registers the same contributor descriptor with no live custody.
type adminRevokeParticipant struct {
	*Repository
	sessions *session.SessionService
	profile  IdentifierAdmissionConfig
	request  session.AdminSessionRevocation
	csrf     session.CSRFKey
	target   adminRevokeTarget
}

var _ kernel.FeatureCommitContributor = (*adminRevokeParticipant)(nil)

func (*adminRevokeParticipant) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{session.AdminSessionRevokeOperation()}
}

func mapAdminRevokeCommand(b identity.CommandBinding, target adminRevokeTarget) (identity.Command, error) {
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: session.AdminSessionRevokeOperation(), Fields: []identity.FeatureField{
		{Name: "target.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: target.digest[:]}},
		{Name: "target.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: target.version}},
	}})
}

func adminRevokeCommand(c identity.Command) (identity.FeatureCommandSpec, uint64, [sha256.Size]byte, error) {
	s, ok := c.Feature()
	var digest [sha256.Size]byte
	if !ok || s.Operation != session.AdminSessionRevokeOperation() || s.Binding.ActorKind != authorization.SubjectUser || len(s.Fields) != 2 {
		return s, 0, digest, session.ErrInvalidSessionCommand
	}
	d, v := s.Fields[0], s.Fields[1]
	if d.Name != "target.digest" || d.Value.Kind != identity.FeatureBytes || len(d.Value.Bytes) != sha256.Size || v.Name != "target.version" || v.Value.Kind != identity.FeatureUint64 || v.Value.Uint64 == 0 || v.Value.Uint64 == ^uint64(0) {
		return s, 0, digest, session.ErrInvalidSessionCommand
	}
	copy(digest[:], d.Value.Bytes)
	if digest == ([sha256.Size]byte{}) {
		return s, 0, digest, session.ErrInvalidSessionCommand
	}
	return s, v.Value.Uint64, digest, nil
}

func (p *adminRevokeParticipant) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	s, version, _, err := adminRevokeCommand(c)
	if p == nil || p.Repository == nil || err != nil || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != s.Operation || plan.SubjectType != "session" || plan.Capability != nil || plan.Lifecycle == nil || *plan.Lifecycle != adminRevokeTransition(version) || len(plan.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := plan.Audits[0]
	if a.EventType != s.Operation.OperationID || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func adminRevokeTransition(version uint64) kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: version, AfterVersion: version + 1}
}

func (p *adminRevokeParticipant) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	var out identity.FeatureReceipt
	if ctx == nil || p == nil || p.Repository == nil {
		return out, session.ErrInvalidSessionCommand
	}
	s, version, digest, err := adminRevokeCommand(c)
	if err != nil {
		return out, err
	}
	b, feature, transition, err := w.FeatureScope(p)
	prepared, present := p.request.Binding()
	if err != nil || !present || b != s.Binding || b != prepared || feature.Operation != s.Operation || transition != adminRevokeTransition(version) || p.target.version != version || p.target.digest != digest {
		return out, session.ErrInvalidSessionCommand
	}
	caller := p.request.Caller()
	actor, err := requireAdminRevocationActor(ctx, w, p, p.profile, b, caller)
	if err != nil {
		return out, err
	}
	if err = p.lockAdminRevokePair(ctx, w, b.TenantID, actor.SessionID, b.RecordID); err != nil {
		return out, err
	}
	if err := p.Repository.requireAdminRevocationSession(ctx, w, p.sessions, p.request, p.csrf); err != nil {
		return out, err
	}
	return p.writeSingleSessionRevocation(ctx, w, b, feature, transition, p.target.record)
}

func requireAdminRevocationActor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, profile IdentifierAdmissionConfig, b identity.CommandBinding, caller session.Session) (session.SessionSpec, error) {
	actor, err := caller.Bindings()
	if err != nil || actor.TenantID != b.TenantID || identity.ActorID(actor.UserID) != b.ActorID {
		return session.SessionSpec{}, identity.ForbiddenError{}
	}
	actorBinding := b
	actorBinding.UserID = actor.UserID
	directory, credential, policy, err := OriginalMFAPasswordSessionAdmission(profile, caller, actorBinding)
	if err != nil {
		return session.SessionSpec{}, identity.ForbiddenError{}
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return session.SessionSpec{}, err
	}
	if _, err = w.RequireActiveActorCredential(ctx, owner, credential); err != nil {
		return session.SessionSpec{}, err
	}
	if err = w.RequireActiveActorAuthorization(ctx, owner, policy); err != nil {
		return session.SessionSpec{}, err
	}
	factor, err := caller.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" {
		return session.SessionSpec{}, identity.ForbiddenError{}
	}
	expected := mfapg.TOTPSessionFactorState{EnrollmentVersion: factor.EnrollmentVersion, AuthorityVersion: factor.FactorAuthorityVersion}
	switch b.OperationID {
	case session.AdminSessionRevokeOperation().OperationID:
		err = mfapg.RequireAdminSessionRevokeActorTOTPSessionFactor(ctx, w, owner, actor.UserID, factor.FactorID, expected)
	case session.AdminSessionRevokeAllOperation().OperationID:
		err = mfapg.RequireAdminSessionRevokeAllActorTOTPSessionFactor(ctx, w, owner, actor.UserID, factor.FactorID, expected)
	default:
		err = identity.ForbiddenError{}
	}
	if err != nil {
		return session.SessionSpec{}, err
	}
	return actor, nil
}

func (r *Repository) requireAdminRevocationSession(ctx context.Context, w kernel.Work, sessions *session.SessionService, req session.AdminSessionRevocation, csrf session.CSRFKey) error {
	cfg := Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}
	if err := RequireCSRF(ctx, w, cfg, req.Caller(), req.CSRFToken(), csrf); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if req.Validate(sessions, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Lock both session IDs in their existing C-collation order before obtaining
// the shared actor-session fence. This prevents cross-revocation lock upgrades
// and also handles the actor revoking the credential used for this request.
func (p *adminRevokeParticipant) lockAdminRevokePair(ctx context.Context, w kernel.Work, tenant identity.TenantID, actor, target string) error {
	rows, err := w.Query(ctx, adminRevokePairSQL(p.schema), string(tenant), actor, target)
	if err != nil {
		return err
	}
	defer rows.Close()
	want := []string{actor}
	if actor != target {
		want = append(want, target)
		slices.Sort(want)
	}
	for _, expected := range want {
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return identity.ConflictError{}
		}
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if id != expected {
			return identity.ConflictError{}
		}
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	return rows.Err()
}

func adminRevokePairSQL(schema string) string {
	return `SELECT session_id FROM ` + schema + `.sessions WHERE tenant_id=$1 AND session_id IN ($2,$3) ORDER BY session_id FOR UPDATE`
}

func (p *adminRevokeParticipant) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if ctx == nil || p == nil || p.Repository == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	return p.recoverSingleSessionRevocation(ctx, w, p, session.AdminSessionRevokeOperation())
}

// CheckFeatureCommit runs after audit, outbox and terminal staging, while
// the same actor authority and both session locks are still held. A wait in
// any of those phases must not carry the original admission past freshness.
func (p *adminRevokeParticipant) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return checkAdminRevocationCommit(ctx, w, p, command, p.request, p.sessions, session.AdminSessionRevokeOperation())
}

func checkAdminRevocationCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, req session.AdminSessionRevocation, sessions *session.SessionService, op identity.FeatureOperation) error {
	b, feature, _, err := w.FeatureScope(owner)
	request, present := req.Binding()
	spec, native := command.Feature()
	if err != nil || !present || !native || b != request || spec.Binding != b || feature.Operation != op || spec.Operation != feature.Operation {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if req.Validate(sessions, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
