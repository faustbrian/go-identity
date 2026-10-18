package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// This phase is private until the owned Send service supplies authentication
// risk admission, recipient resolution and same-code generation/rendering. It
// must not become a public constructor accepting caller-selected risk results.
// It composes the real digest store and encrypted-effect owner in the existing
// coordinator, without a second transaction, journal, provider or callback.
type issuanceContributor struct {
	store    *Contributor
	delivery *deliverypg.Contributor
	prepared deliverypg.PreparedDelivery
}

func newIssuanceContributor(store *Contributor, delivery *deliverypg.Contributor, prepared deliverypg.PreparedDelivery) (*issuanceContributor, error) {
	plan, err := prepared.Plan()
	if store == nil || store.codec == nil || delivery == nil || err != nil || plan.Contributor != delivery.Descriptor() || len(plan.Intents) != 1 {
		return nil, ErrInvalidCommand
	}
	return &issuanceContributor{store: store, delivery: delivery, prepared: prepared}, nil
}

func (*issuanceContributor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.issuance(redacted)"))
}
func (*issuanceContributor) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (*issuanceContributor) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

func (*issuanceContributor) Descriptor() kernel.ContributorDescriptor {
	return (*Contributor)(nil).Descriptor()
}

func (p *issuanceContributor) FeatureOperations() []identity.FeatureOperation {
	if p == nil || p.store == nil {
		return nil
	}
	return []identity.FeatureOperation{issuanceOperation(identity.FeatureSubjectUser), issuanceOperation(identity.FeatureSubjectAnonymousFlow)}
}

func (p *issuanceContributor) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
	if p == nil || p.store == nil || !ok || spec.Operation != issuanceOperation(spec.Operation.SubjectRequirement) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "otp_challenge" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "otp.sent.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 || len(plan.Audits) != 1 || plan.Audits[0].EventType != "otp.send" || plan.OTP != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || plan.CaptchaReplayReservation || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery == nil || len(spec.Fields) != 2 {
		return ErrInvalidCommand
	}
	delivery, err := p.prepared.Plan()
	if err != nil || delivery.Contributor != plan.Delivery.Contributor || len(plan.Delivery.Intents) != 1 || len(delivery.Intents) != 1 || delivery.Intents[0] != plan.Delivery.Intents[0] {
		return ErrInvalidCommand
	}
	return p.validateIssuanceDelivery(command)
}

// This validates immutable challenge/delivery custody only; current authority
// and the actual registered feature declaration are independently required.
func (p *issuanceContributor) validateIssuanceDelivery(command identity.Command) error {
	if p == nil || p.store == nil || p.prepared == (deliverypg.PreparedDelivery{}) {
		return ErrInvalidCommand
	}
	spec, ok := command.Feature()
	if !ok || len(spec.Fields) != 2 {
		return ErrInvalidCommand
	}
	delivery, err := p.prepared.Plan()
	if err != nil || len(delivery.Intents) != 1 || delivery.Contributor != p.delivery.Descriptor() {
		return ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(context.Background(), p.store.codec.maximumDuration)
	defer stop()
	custody, _, err := p.store.authenticateIssuance(ctx, command)
	if err != nil {
		return err
	}
	s, _ := custody.challenge.Bindings()
	b, _ := s.Continuation.Bindings()
	target := string(spec.Binding.UserID)
	if target == "" {
		target = spec.Binding.AnonymousFlowID
	}
	intent := delivery.Intents[0]
	if intent.Purpose != "otp-"+string(b.Scope.Purpose) || intent.SubjectID != target || !intent.ExpiresAt.Equal(s.ExpiresAt) {
		return ErrInvalidCommand
	}
	return nil
}

func (p *issuanceContributor) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	return p.applyIssuance(ctx, w, command, p)
}

// Invocation custody is local; all Work authorization uses the stable owner.
func (p *issuanceContributor) applyIssuance(ctx context.Context, w kernel.Work, command identity.Command, owner kernel.FeatureExecutionContributor) (identity.FeatureReceipt, error) {
	bad := func(err error) (identity.FeatureReceipt, error) { return identity.FeatureReceipt{}, err }
	if p == nil || p.store == nil || ctx == nil {
		return bad(ErrInvalidCommand)
	}
	binding, registration, transition, err := w.FeatureScope(owner)
	if err != nil {
		return bad(err)
	}
	spec, ok := command.Feature()
	op, opErr := boundIssuanceOperation(binding)
	if !ok || opErr != nil || binding != spec.Binding || registration.Operation != spec.Operation || spec.Operation != op {
		return bad(ErrInvalidCommand)
	}
	if op == mfaEnrollmentSendOperation() {
		if transition.EventType != "otp.sent.v1" || registration.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || transition.BeforeVersion == 0 || transition.BeforeVersion == ^uint64(0) || transition.AfterVersion != transition.BeforeVersion+1 {
			return bad(ErrInvalidCommand)
		}
	} else if op == mfaLoginSendOperation() {
		if transition.EventType != "otp.sent.v1" || registration.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
			return bad(ErrInvalidCommand)
		}
	} else if op == phoneEnrollmentSendOperation() {
		if transition.EventType != "identifier.attached.v1" || registration.Contributor != (kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
			return bad(ErrInvalidCommand)
		}
	} else if transition.EventType != "otp.sent.v1" || registration.Contributor != p.Descriptor() || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return bad(ErrInvalidCommand)
	}
	custody, flow, err := p.store.authenticateIssuance(ctx, command)
	if err != nil {
		return bad(err)
	}
	if op == phoneEnrollmentSendOperation() && custody.recipient != nil {
		return bad(ErrInvalidCommand)
	}
	a := custody.authority
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, a.Directory); err != nil {
		return bad(err)
	}
	if binding.UserID != "" {
		expected := kernel.UserAuthorityAdmission{UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}
		if err := w.RequireActiveUserAuthority(ctx, owner, expected); err != nil {
			return bad(err)
		}
		if a.Credential != (identity.CredentialRef{}) {
			if _, err := w.RequireActiveCredential(ctx, owner, issuanceCredential(a)); err != nil {
				return bad(err)
			}
		}
		if err := w.RequireActiveUserAuthorization(ctx, owner, a.UserAuthorization); err != nil {
			return bad(err)
		}
	}
	// Keep the same order as verification: primary owners, original flow,
	// destination/subject abuse, send family, then predecessor challenges.
	if err := requireNativeFlow(ctx, w, p.store, flow, nil); err != nil {
		return bad(err)
	}
	if custody.recipient != nil {
		selected := *custody.recipient
		if op == mfaLoginSendOperation() {
			// Preserve the sealed user-bound source unchanged. The kernel's
			// anonymous command reader uses canonical lookup, but still fences
			// every actual selected-user/identifier/credential epoch and ID.
			// Original MFA correlation already binds this exact resolved user.
			selected.Query.UserID = ""
		}
		if err := w.RequireRecipient(ctx, owner, selected); err != nil {
			return bad(err)
		}
	}
	s, _ := custody.challenge.Bindings()
	if p.store.emailVerification != nil {
		if err := p.store.admitEmailVerificationSend(ctx, w, owner, command, s.Continuation, custody.recipient); err != nil {
			return bad(err)
		}
	}
	if p.store.emailChange != nil {
		original := sendRequestRecord{continuation: s.Continuation, recipient: custody.recipient, authority: a, expiresAt: s.ExpiresAt}
		if err := p.store.admitEmailChangeSend(ctx, w, owner, command, original); err != nil {
			return bad(err)
		}
	}
	continuation, _ := s.Continuation.Bindings()
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	if err := p.store.lockout.initializeLockouts(ctx, query, w.Exec, p.store.schema, continuation.Scope); err != nil {
		return bad(err)
	}
	if _, _, err := p.store.lockout.loadLockouts(ctx, query, p.store.schema, continuation.Scope); err != nil {
		return bad(err)
	}
	if err := p.store.lockout.initializeSendFamily(ctx, query, w.Exec, p.store.schema, continuation.Scope); err != nil {
		return bad(err)
	}
	family, err := p.store.lockout.loadSendFamily(ctx, query, p.store.schema, continuation.Scope)
	if err != nil {
		return bad(err)
	}
	now, err := p.currentTime(ctx, w, a, flow, s, owner)
	if err != nil {
		return bad(err)
	}
	if err := p.store.lockout.persistIssuance(ctx, query, w.Exec, p.store.codec, family, custody.challenge, binding, now); err != nil {
		return bad(err)
	}
	// Predecessor locking can wait too. Earlier successful reads and locks
	// preserve identities, not expiry or freshness; a late denial rolls back
	// the family append, replacement and new challenge in the same Work.
	if _, err := p.currentTime(ctx, w, a, flow, s, owner); err != nil {
		return bad(err)
	}
	if err := p.delivery.Stage(ctx, w, p.prepared); err != nil {
		return bad(err)
	}
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: transition.BeforeVersion, AfterVersion: transition.AfterVersion}, nil
}

func issuanceCredential(a AttemptAuthority) kernel.CredentialAdmission {
	return kernel.CredentialAdmission{Credential: a.Credential, UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}
}

func (p *issuanceContributor) currentTime(ctx context.Context, w kernel.Work, a AttemptAuthority, flow nativeFlow, challenge otp.ChallengeSpec, owner kernel.FeatureExecutionContributor) (time.Time, error) {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if a.Credential != (identity.CredentialRef{}) {
		now, err = w.RequireActiveCredential(ctx, owner, issuanceCredential(a))
		if err != nil {
			return time.Time{}, err
		}
	}
	if now.Before(challenge.IssuedAt) || !now.Before(challenge.ExpiresAt) || p.store.flowTime(flow, now) != nil {
		return time.Time{}, ErrInvalidCommand
	}
	return now, nil
}

func (p *issuanceContributor) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.recoverIssuance(ctx, w, p)
}

func (p *issuanceContributor) recoverIssuance(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if p == nil || p.store == nil || ctx == nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	b, registration, _, err := w.FeatureScope(owner)
	op, opErr := boundIssuanceOperation(b)
	if err != nil || opErr != nil || registration.Operation != op {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	id, ok := ownershipID(string(b.CommandID))
	if !ok {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	// Any retained effect blocks a negative vote. Challenge tombstones remain
	// durable through key retirement; absent delivery payload is not rollback
	// proof and no current flow, code or replacement may be reconstructed here.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+pgx.Identifier{p.store.schema}.Sanitize()+`.challenges WHERE tenant_id=$1 AND issue_command_id=$2 AND issue_command_purpose=$3)`, string(b.TenantID), id, b.OperationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, ErrUnavailable
	}
	if exists {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

var _ kernel.FeatureExecutionContributor = (*issuanceContributor)(nil)
