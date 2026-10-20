package postgres

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// OAuthReauthenticationRequiredError classifies an OAuth authentication-age
// denial, distinct from provider failure. Only its coordinator-owned terminal
// NotCommitted receipt proves noncommit; this error alone does not. It carries
// no credential or retry permission. Only a separately admitted
// genuine authentication may request the closed continuation handoff below.
// Install OAuthReauthenticationMigrationSource before enabling this profile;
// existing terminal receipts and their classifications remain immutable.
type OAuthReauthenticationRequiredError struct{}

func (OAuthReauthenticationRequiredError) Error() string {
	return "identity postgres: OAuth reauthentication required"
}

// OAuthContinuationPreparationContributor opts the canonical OAuth native
// continuation owner into a new attempt AFTER its previous attempt is proven
// terminal reauthentication-required/NotCommitted by this coordinator. The
// pure selector returns zero/false for ordinary preparation. Advance runs only
// after ordinary current admission and locked same-human/flow predecessor proof,
// in the SAME transaction as the acknowledged preparation-start marker.
//
// Advance must first call RequireOAuthContinuationHandoff, then CAS only its
// existing active continuation's attempt pointer from previous to this command.
// It must preserve the original token/request/expiry and require genuine newer
// authentication, original/current authority and the original deadline after
// waits. No code, consent, grant authority, effect or independent outcome store
// may be created here. No mutation is permitted in AdmitFeaturePreparation.
// Pending, unknown, committed and other failed predecessors never unlock it.
// Failed/ambiguous start never authorizes generation or another handoff.
// Advance is synchronous, bounded and callback-only; close rows, retain no Work,
// perform no external IO/crypto/generation/retries or transaction closure.
type OAuthContinuationPreparationContributor interface {
	FeaturePreparationContributor
	OAuthContinuationHandoff(identity.Command) (previous identity.CommandID, requested bool, err error)
	AdvanceOAuthContinuation(context.Context, Work, identity.Command, identity.CommandID) error
}

type oauthContinuationHandoff struct {
	owner    OAuthContinuationPreparationContributor
	command  identity.Command
	previous identity.CommandID
}

// RequireOAuthContinuationHandoff admits only the exact original command and
// predecessor during this owner's checked preparation-start callback. Ordinary
// admission, Apply, foreign, zero and returned handles deny and poison live Work.
// It performs no IO or authorization renewal and proves neither start COMMIT nor
// credential issuance. Advance must separately enforce its native pointer CAS.
func (w Work) RequireOAuthContinuationHandoff(ctx context.Context, owner OAuthContinuationPreparationContributor, command identity.Command, previous identity.CommandID) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	s := w.state.oauthHandoff
	if s == nil || !sameParticipant(s.owner, owner) || !sameParticipant(w.state.featureInvocation, owner) || s.command != command || s.previous != previous || w.state.featureApplying || w.state.execution != nil {
		return w.fail(ctx, invalidWork())
	}
	return nil
}

func oauthContinuationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.continue", SchemaID: "identity.oauth-server.continue.public-password-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func oauthReauthenticationOperation(op identity.FeatureOperation) bool {
	if op == oauthContinuationOperation() {
		return true
	}
	return op == (identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.authorize", SchemaID: "identity.oauth-server.authorize.public-password-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired})
}

func oauthReauthenticationFeature(feature *FeatureRegistration) bool {
	return feature != nil && oauthReauthenticationOperation(feature.Operation) && feature.Contributor == (ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1})
}

func oauthContinuationHandoffScope(current, previous identity.CommandBinding) bool {
	op := oauthContinuationOperation()
	if current.ValidateFor(op) != nil || previous.ValidateFor(op) != nil || current.CommandID == previous.CommandID || current.UserID == "" || current.AnonymousFlowID != "" || previous.AnonymousFlowID != "" || current.ActorKind != authorization.SubjectUser || previous.ActorKind != authorization.SubjectUser || current.ActorID != identity.ActorID(current.UserID) || previous.ActorID != identity.ActorID(previous.UserID) || current.CorrelationID != string(current.CommandID) || previous.CorrelationID != string(previous.CommandID) {
		return false
	}
	return current.TenantID == previous.TenantID && current.UserID == previous.UserID && current.ActorID == previous.ActorID && current.RecordID == previous.RecordID && current.PolicyID == previous.PolicyID && current.PolicyVersion == previous.PolicyVersion && current.LinkMode == previous.LinkMode
}

func (c *Coordinator) advanceOAuthContinuationPreparation(ctx context.Context, tx pgx.Tx, command identity.Command, q claimRequest, p *admittedKernelPlan, phase FeaturePreparationContributor, journal journalReservation, leaseOwner [16]byte, external bool) (err error) {
	owner, selected := phase.(OAuthContinuationPreparationContributor)
	if !selected {
		return nil
	}
	previous, requested, err := owner.OAuthContinuationHandoff(command)
	if err != nil || !requested && previous != "" {
		return invalidPreparation()
	}
	if !requested {
		return nil
	}
	if external || p.feature == nil || p.feature.Operation != oauthContinuationOperation() || p.feature.Contributor != (ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}) || p.binding.CommandID == previous {
		return invalidPreparation()
	}
	if _, err := identity.ParseCommandID(string(previous)); err != nil {
		return invalidPreparation()
	}
	entry, err := c.registry.selectFeatureOperation(*p.feature)
	if err != nil || !sameParticipant(entry.contributor, owner) {
		return invalidPreparation()
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(previous))
	var locked []byte
	// Use the existing recovery exclusion order and decoder. An expired lease,
	// absent receipt or failed observation is never proof of noncommit.
	if err := tx.QueryRow(ctx, `SELECT command_id FROM identity.identity_command_id_claims WHERE command_id=$1 FOR UPDATE`, id).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ForbiddenError{}
		}
		return readFailure(ctx, err)
	}
	if err := tx.QueryRow(ctx, `SELECT command_id FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 FOR UPDATE`, id, string(p.binding.TenantID), p.binding.OperationID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ForbiddenError{}
		}
		return readFailure(ctx, err)
	}
	query := identity.RecoveryQuery{CommandID: previous, TenantID: p.binding.TenantID, UserID: p.binding.UserID, ActorID: p.binding.ActorID, ActorKind: p.binding.ActorKind, OperationID: p.binding.OperationID, RecordID: p.binding.RecordID, LinkMode: p.binding.LinkMode}
	observed, readErr := readRecoveryObservation(ctx, tx, id)
	receipt, receiptErr := commandReceipt(query, observed, readErr)
	var reauthenticate OAuthReauthenticationRequiredError
	if receipt.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(receiptErr, &reauthenticate) || !oauthContinuationHandoffScope(p.binding, receipt.Binding) || receipt.Feature == nil || receipt.Feature.Operation != p.feature.Operation {
		return identity.ForbiddenError{}
	}
	previousPlan, preparationOnly, err := observedCommandPlan(receipt.Binding, &receipt.Feature.Operation, observed)
	if err != nil || preparationOnly || previousPlan.Feature == nil || *previousPlan.Feature != *p.feature || previousPlan.Lifecycle == nil || p.lifecycle == nil || *previousPlan.Lifecycle != *p.lifecycle {
		return identity.ForbiddenError{}
	}
	fence, err := beginJournal(ctx, tx, q, c.keys, journal, leaseOwner)
	if err != nil {
		return err
	}
	w, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return err
	}
	defer func() {
		invalidateWork(w)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	w.state.registry = c.registry.state
	if err := p.bindWork(w); err != nil {
		return err
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return err
	}
	w.state.featureInvocation = owner
	w.state.oauthHandoff = &oauthContinuationHandoff{owner: owner, command: command, previous: previous}
	defer func() {
		w.state.oauthHandoff = nil
		w.state.featureInvocation = nil
	}()
	if err := owner.AdvanceOAuthContinuation(ctx, w, command, previous); err != nil {
		return err
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
