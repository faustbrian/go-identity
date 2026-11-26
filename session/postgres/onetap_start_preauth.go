package postgres

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

const oneTapStartPreAuthField = "preauth.commitment"

// OneTapStartPreAuthField commits the entire original Google browser flow and
// cookie digest without exposing either. Only the trusted OAuth preparation
// owner supplies this field on its prepared command, never browser input.
func OneTapStartPreAuthField(record session.PreAuthTransaction) (identity.FeatureField, error) {
	bound, err := record.ProviderBindings()
	if err != nil || !oneTapPreAuthProvider(bound.Provider) || !validOneTapStartRecord(bound.Transaction) {
		return identity.FeatureField{}, session.ErrInvalidPreAuthTransaction
	}
	digest, err := preAuthIssueRecordDigest(record)
	if err != nil {
		return identity.FeatureField{}, err
	}
	return identity.FeatureField{Name: oneTapStartPreAuthField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
}

// StageOneTapStartPreAuth writes the exact prepared flow and retained evidence
// inside the OAuth owner's coordinator Work. The owner must propagate failure
// and stage the related callback grant in that same transaction. This method
// neither commits, validates that grant, nor releases any browser credential.
func StageOneTapStartPreAuth(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, c Config, record session.PreAuthTransaction, selected session.PreAuthProviderBinding) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !isOneTapStartPreAuthScope(b, feature, lifecycle) {
		return session.ErrInvalidPreAuthTransaction
	}
	if err := validateOneTapStartPreAuth(b, command, record, selected); err != nil {
		return err
	}
	return stagePreAuthIssue(ctx, w, c, b, record, selected)
}

// RecoverOneTapStartPreAuth returns only exact historical storage evidence in
// the OAuth participant's recovery invocation. A retired live flow does not
// imply rollback. The coordinator still owns the overall recovery outcome.
func RecoverOneTapStartPreAuth(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, c Config) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !isOneTapStartPreAuthScope(b, feature, lifecycle) {
		return kernel.RecoveryUnknown, session.ErrInvalidPreAuthTransaction
	}
	return readPreAuthIssueEvidence(ctx, w, c, b)
}

func isOneTapStartPreAuthScope(b identity.CommandBinding, feature kernel.FeatureRegistration, lifecycle kernel.LifecyclePlan) bool {
	op := kernel.OneTapStartOperation()
	return feature.Operation == op && b.ValidateFor(op) == nil && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == b.AnonymousFlowID &&
		lifecycle == (kernel.LifecyclePlan{EventType: "session.preauth-issued.v1", AfterVersion: 1})
}

func validOneTapStartRecord(p session.PreAuthTransactionSpec) bool {
	i := p.Binding.Intent
	return p.Version == 1 && i.Action == kernel.OneTapStartOperation().OperationID && i.Purpose == session.PreAuthSessionIssuance &&
		i.CallbackURL == "" && strings.HasPrefix(i.Origin, "https://") && p.Binding.ExpiresAt.Sub(p.Binding.IssuedAt) == 5*time.Minute
}

func validateOneTapStartPreAuth(b identity.CommandBinding, command identity.Command, record session.PreAuthTransaction, selected session.PreAuthProviderBinding) error {
	op := kernel.OneTapStartOperation()
	if b.ValidateFor(op) != nil || !oneTapPreAuthProvider(selected) {
		return session.ErrInvalidPreAuthTransaction
	}
	spec, ok := command.Feature()
	if !ok || spec.Operation != op || spec.Binding != b {
		return session.ErrInvalidPreAuthTransaction
	}
	p, err := selectedPreAuthProjection(record, selected)
	if err != nil || b.RecordID != string(p.Binding.ID) || b.AnonymousFlowID != string(p.Binding.ID) || b.TenantID != p.Binding.Intent.TenantID ||
		b.PolicyID != p.Binding.Intent.PolicyID || b.PolicyVersion != p.Binding.Intent.PolicyVersion {
		return session.ErrInvalidPreAuthTransaction
	}
	want, err := OneTapStartPreAuthField(record)
	if err != nil {
		return err
	}
	for _, field := range spec.Fields {
		if field.Name == oneTapStartPreAuthField && field.Value.Kind == identity.FeatureBytes && subtle.ConstantTimeCompare(field.Value.Bytes, want.Value.Bytes) == 1 {
			return nil
		}
	}
	return session.ErrInvalidPreAuthTransaction
}
