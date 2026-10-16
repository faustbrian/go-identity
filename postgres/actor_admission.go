package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequireActiveActorCredential checks the immutable command's human actor,
// independently of its target UserID, through the existing primary credential
// owner. All original credential/user/identifier epochs must match. Locks and
// bounded database-time checks match RequireActiveCredential; neither method
// changes command scope or grants permission, authentication or proof use.
// A missing/foreign actor or invocation poisons live Work. The native owner
// must freeze expected input, acquire cross-subject locks in canonical order,
// check every other authority and consume fresh proof atomically.
func (w Work) RequireActiveActorCredential(ctx context.Context, p FeatureExecutionContributor, expected CredentialAdmission) (time.Time, error) {
	b, err := w.actorAdmissionBinding(ctx, p)
	if err != nil {
		return time.Time{}, err
	}
	return w.requireActiveCredential(ctx, b, expected)
}

// RequireActiveActorAuthorization compares the original human actor's exact
// authorization epoch, not the target user's epoch. Scope.SubjectID must equal
// immutable ActorID; the existing authorization owner retains its share lock
// within Work. Errors poison Work. This is not an Allow decision, proof or
// freshness renewal; the workflow still requires current target authorization.
func (w Work) RequireActiveActorAuthorization(ctx context.Context, p FeatureExecutionContributor, expected UserAuthorizationAdmission) error {
	b, err := w.actorAdmissionBinding(ctx, p)
	if err != nil {
		return err
	}
	return w.requireActiveUserAuthorization(ctx, b, expected)
}

func (w Work) actorAdmissionBinding(ctx context.Context, p FeatureExecutionContributor) (identity.CommandBinding, error) {
	if err := w.usable(); err != nil {
		return identity.CommandBinding{}, err
	}
	if ctx == nil {
		return identity.CommandBinding{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return identity.CommandBinding{}, w.fail(ctx, err)
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil || b.ActorKind != authorization.SubjectUser || b.ActorID == "" || b.UserID == "" || b.AnonymousFlowID != "" {
		return identity.CommandBinding{}, w.fail(ctx, invalidWork())
	}
	// This local owner lookup key is not a replacement command. Work's frozen
	// binding remains target-scoped for policy, writes, audit and recovery.
	b.UserID = identity.UserID(b.ActorID)
	return b, nil
}
