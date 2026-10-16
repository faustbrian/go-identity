package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequireEmailRemovalSubjects fences the original global/tenant epochs, then
// acquires both administrative actor and target user rows in one canonical
// primary order before either owner's credential/factor/session checks. The
// exact email participant may call it only during original preparation or Apply.
// Kernel removal execution repeats the same fence before locking identifiers.
// This prevents reciprocal/cyclic cross-subject removal lock inversion.
//
// The three expected values must match immutable command fields. No command
// scope, versions or state are changed, no missing account is created and no
// authentication/permission/proof admission is granted. Missing/foreign scope,
// returned invocation, deadline or storage failure poisons Work. The coordinator
// alone owns the transaction; locks remain until its commit or rollback.
func (w Work) RequireEmailRemovalSubjects(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected EmailRemovalAdministration) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidEmailRemoval())
	}
	b, f, _, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	original := w.state.featurePreparationCommand != nil && *w.state.featurePreparationCommand == command || w.state.featureApplyCommand != nil && *w.state.featureApplyCommand == command
	if err != nil || !ok || !original || s.Binding != b || s.Operation != emailRemovalOperation() || f.Operation != s.Operation || f.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || !expected.valid(b.TenantID) {
		return w.fail(ctx, invalidEmailRemoval())
	}
	matched := uint8(0)
	for _, field := range s.Fields {
		switch field.Name {
		case "email-removal.actor-global":
			if matched&1 != 0 || field.Value.Kind != identity.FeatureText || field.Value.Text != expected.GlobalAuthorityID {
				return w.fail(ctx, invalidEmailRemoval())
			}
			matched |= 1
		case "email-removal.actor-global-version":
			if matched&2 != 0 || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != expected.GlobalVersion {
				return w.fail(ctx, invalidEmailRemoval())
			}
			matched |= 2
		case "email-removal.actor-tenant-version":
			if matched&4 != 0 || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != expected.TenantVersion {
				return w.fail(ctx, invalidEmailRemoval())
			}
			matched |= 4
		}
	}
	if matched != 7 {
		return w.fail(ctx, invalidEmailRemoval())
	}
	return lockEmailRemovalSubjects(ctx, w, b, expected)
}

func lockEmailRemovalSubjects(ctx context.Context, w Work, b identity.CommandBinding, expected EmailRemovalAdministration) error {
	if b.ActorKind != authorization.SubjectUser || b.ActorID == "" || b.UserID == "" || b.AnonymousFlowID != "" || string(b.ActorID) == string(b.UserID) || !expected.valid(b.TenantID) {
		return w.fail(ctx, invalidEmailRemoval())
	}
	if err := w.requireActiveDirectoryAuthority(ctx, b, expected.directory(b.TenantID)); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id IN($2,$3) ORDER BY user_id FOR UPDATE`, string(b.TenantID), string(b.ActorID), string(b.UserID))
	if err != nil {
		return err
	}
	count := 0
	seen := map[string]bool{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || count >= 2 || seen[id] || id != string(b.ActorID) && id != string(b.UserID) {
			rows.Close()
			return w.fail(ctx, identity.UnavailableError{})
		}
		seen[id] = true
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return w.fail(ctx, err)
	}
	if count != 2 {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	return w.usable()
}
