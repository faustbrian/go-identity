package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func (r *Repository) prepareAdministrativeAttributes(spec identity.UpdateUserCommand) (registeredSchema, []byte, error) {
	registered, ok := r.attributeSchemas[schemaKey{spec.Binding.SchemaID, spec.Binding.SchemaVersion}]
	if !ok {
		return registeredSchema{}, nil, attributeStorageError()
	}
	for _, update := range spec.Attributes {
		found := false
		for _, field := range registered.schema.Fields {
			if field.Name != update.Name {
				continue
			}
			if field.InputPermission != identity.FieldWrite && field.InputPermission != identity.FieldReadWrite || field.WriteAuthorization == identity.FieldWriteSelf && (spec.Binding.ActorKind != authorization.SubjectUser || string(spec.Binding.ActorID) != string(spec.Binding.UserID)) {
				return registeredSchema{}, nil, identity.ForbiddenError{}
			}
			found = true
			break
		}
		if !found {
			return registeredSchema{}, nil, attributeStorageError()
		}
	}
	encoded, err := encodeAttributeDocument(registered.schema, spec.Attributes)
	return registered, encoded, err
}

// ApplyUserUpdate applies a constructor-validated administrative field command
// through this exact enlisted Repository's Work. It grants no policy authority.
// The locked nonterminal status and exact aggregate version fence one successor;
// whole values replace named fields, preserving omissions and explicit zeros.
// It does not modify names, images, status, credentials or identifiers. Unknown
// or mismatched schemas fail closed, and every error poisons Work for Abort.
// The returned structural user is provisional, never a durable commit receipt.
func (r *Repository) ApplyUserUpdate(ctx context.Context, w Work, command identity.Command) (identity.User, error) {
	if _, err := r.applyAttributeUpdate(ctx, w, command, true); err != nil {
		return identity.User{}, err
	}
	return *w.state.update, nil
}
