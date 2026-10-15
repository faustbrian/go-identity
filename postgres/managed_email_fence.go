package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// The optional field is authenticated original command intent. The closed
// owner validates it against signed family metadata before executing. Acquire
// the same capability-owned advisory protocol before directory/factor locks,
// not from inside ApplyFeature after those locks have already been obtained.
func lockManagedEmailFamily(ctx context.Context, w Work, c identity.Command) error {
	s, ok := c.Feature()
	if !ok {
		return nil
	}
	var family []byte
	for _, f := range s.Fields {
		if f.Name == "email.management.family" {
			if family != nil || f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) != 32 {
				return w.fail(ctx, invalidEmailAttachment())
			}
			family = f.Value.Bytes
		}
	}
	if family == nil {
		if s.Operation == emailResendOperation() {
			return w.fail(ctx, invalidEmailAttachment())
		}
		return nil
	}
	if !emailAttachmentOperation(s.Operation) && !managedEmailConfirmationOperation(s.Operation) || w.state.feature.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) {
		return w.fail(ctx, invalidEmailAttachment())
	}
	n, err := w.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),0))`, family)
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	return nil
}
