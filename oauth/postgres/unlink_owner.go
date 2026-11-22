package postgres

import (
	"context"
	"crypto/subtle"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// A phase is request-local: it never shares its original password or journal
// admission time with another request. Only the coordinator owns SQL Work.
type rpUnlinkPhase struct {
	service      *LinkService
	original     identity.Command
	primary      passwordpg.AccountUnlinkPrimaryAdmission
	password     identity.CredentialRef
	admissionErr error
	declaration  kernel.CommandPlan
	admittedAt   time.Time
}

var _ kernel.AccountUnlinkPreparationContributor = (*rpUnlinkPhase)(nil)

func (*rpUnlinkPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-unlink", Version: 1}
}

func (p *rpUnlinkPhase) matchesOriginal(candidate identity.Command) bool {
	a, ab, valid := p.original.AccountUnlinkPreparationInput()
	b, bb, ok := candidate.AccountUnlinkPreparationInput()
	return valid && ok && reflect.DeepEqual(a, b) && subtle.ConstantTimeCompare([]byte(ab.Token()), []byte(bb.Token())) == 1
}

func (p *rpUnlinkPhase) ValidateAccountUnlinkPreparation(original identity.Command, plan kernel.CommandPlan) error {
	if !p.matchesOriginal(original) || !sameRPLinkDeclaration(p.declaration, plan) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpUnlinkPhase) AdmitAccountUnlinkPreparation(ctx context.Context, w kernel.AccountUnlinkPreparationWork, original identity.Command) error {
	if p.admissionErr != nil {
		return p.admissionErr
	}
	if !p.matchesOriginal(original) || p.password.ID == "" {
		return identity.ForbiddenError{}
	}
	if err := p.primary.AdmitPreparation(ctx, w, p); err != nil {
		return err
	}
	if _, err := mfapg.RequireOAuthUnlinkPreparationFactors(ctx, w, p); err != nil {
		return err
	}
	admitted, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	p.admittedAt = admitted.UTC()
	return nil
}

func (p *rpUnlinkPhase) GenerateAccountUnlinkPreparation(ctx context.Context, original identity.Command, generation uint64) ([]byte, error) {
	if !p.matchesOriginal(original) || p.admittedAt.IsZero() {
		return nil, identity.ForbiddenError{}
	}
	deadline, err := p.primary.Deadline()
	if err != nil {
		return nil, err
	}
	return p.service.sealUnlinkOutput(ctx, original, generation, p.admittedAt, deadline.UTC())
}

func (p *rpUnlinkPhase) RestoreAccountUnlinkPreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, kernel.CapabilityIssuancePlan, error) {
	if !p.matchesOriginal(original) {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, identity.ForbiddenError{}
	}
	command, issuance, err := p.service.restoreUnlinkOutput(ctx, original, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, err
	}
	plan := p.declaration
	plan.Capability = &issuance.Grants[0]
	return command, plan, issuance, nil
}

func (*rpUnlinkPhase) PrepareAccountUnlink(context.Context, identity.Command) (identity.Command, kernel.CommandCounterPlan, kernel.CapabilityPlan, error) {
	return identity.Command{}, kernel.CommandCounterPlan{}, kernel.CapabilityPlan{}, identity.ForbiddenError{}
}

func (p *rpUnlinkPhase) ValidateAccountUnlink(command identity.Command, plan kernel.CommandPlan) error {
	actual, counters, ok := command.AccountUnlinkCounterCommand()
	want, _, valid := p.original.AccountUnlinkPreparationInput()
	if !ok || !valid || actual.Binding != want.Binding || actual.Change != want.Change || actual.SessionID != want.SessionID ||
		actual.SessionVersion != want.SessionVersion || actual.RevokeProvider || !reflect.DeepEqual(counters, want.Counters) ||
		plan.Capability == nil || plan.Capability.ProofFingerprint != actual.Proof.EnvelopeDigest() {
		return identity.ForbiddenError{}
	}
	plan.Capability = nil
	if !sameRPLinkDeclaration(p.declaration, plan) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpUnlinkPhase) CheckAccountUnlink(ctx context.Context, w kernel.AccountUnlinkWork) error {
	if p.admissionErr != nil {
		return p.admissionErr
	}
	spec, _, err := w.Command(p)
	if err != nil {
		return err
	}
	original, wire, generation, err := w.Preparation(p)
	defer clear(wire)
	if err != nil {
		return err
	}
	command, plan, _, err := p.RestoreAccountUnlinkPreparation(ctx, original, generation, wire)
	restored, _, ok := command.AccountUnlinkCounterCommand()
	if err != nil || !ok || restored.Proof.EnvelopeDigest() != spec.Proof.EnvelopeDigest() {
		return identity.ForbiddenError{}
	}
	if err := p.ValidateAccountUnlink(command, plan); err != nil {
		return err
	}
	if err := p.primary.RequireCurrent(ctx, w, p); err != nil {
		return err
	}
	_, err = mfapg.RequireOAuthUnlinkFactors(ctx, w, p)
	return err
}

func (p *rpUnlinkPhase) EligibleAccountUnlinkMethods(ctx context.Context, w kernel.AccountUnlinkWork, methods []identity.LoginMethod) ([]identity.LoginMethod, error) {
	if _, _, err := w.Command(p); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	markIndependentUnlinkPassword(methods, p.password)
	return methods, nil
}

func markIndependentUnlinkPassword(methods []identity.LoginMethod, ref identity.CredentialRef) {
	for i := range methods {
		methods[i].Usable = ref.ID != "" && methods[i].AccountID == "" && methods[i].Credential == ref
	}
}

func (p *rpUnlinkPhase) PersistAccountUnlink(ctx context.Context, w kernel.AccountUnlinkWork) error {
	if err := p.primary.Consume(ctx, w, p); err != nil {
		return err
	}
	return eraseAccountUnlinkVault(ctx, w, p, p.service.config().Schema)
}

func (p *rpUnlinkPhase) FinalizeAccountUnlink(ctx context.Context, w kernel.AccountUnlinkWork) error {
	if err := p.primary.RequireConsumed(ctx, w, p); err != nil {
		return err
	}
	spec, _, err := w.Command(p)
	if err != nil {
		return err
	}
	exists, err := p.vaultExists(ctx, w.Query, spec.Binding, 0)
	if err != nil {
		return err
	}
	if exists {
		return identity.ConflictError{}
	}
	return nil
}

func (p *rpUnlinkPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, before, err := w.AccountUnlinkScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	unused, err := passwordpg.AccountUnlinkPasswordNotConsumed(ctx, w, p)
	if err != nil || !unused {
		return kernel.RecoveryUnknown, err
	}
	intact, err := p.vaultExists(ctx, w.Query, b, before)
	if err != nil || !intact {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryNotCommitted, nil
}

func (p *rpUnlinkPhase) vaultExists(ctx context.Context, query func(context.Context, string, ...any) (*kernel.WorkRows, error), b identity.CommandBinding, before uint64) (bool, error) {
	sql := `SELECT EXISTS(SELECT 1 FROM ` + rpQuotedSchema(p.service.config().Schema) + `.token_sets
WHERE tenant_id=$1 AND account_id=$2 AND user_id=$3`
	args := []any{string(b.TenantID), b.RecordID, string(b.UserID)}
	if before > 0 {
		sql += ` AND account_version=$4::numeric`
		args = append(args, before)
	}
	rows, err := query(ctx, sql+`)`, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return false, identity.UnavailableError{}
	}
	return exists, nil
}
