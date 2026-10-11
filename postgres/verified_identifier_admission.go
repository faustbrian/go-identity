package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// VerifiedIdentifierAdmission retains a passwordless session's original exact
// verified identifier and all three user security epochs. It is neither bearer
// authentication nor a substitute credential. Kind is email or phone; versions
// are positive. The command binds tenant/user and the caller freezes these
// values in its original intent before reservation. Diagnostic export denies.
type VerifiedIdentifierAdmission struct {
	IdentifierID                           identity.IdentifierID
	Kind                                   identity.IdentifierKind
	IdentifierVersion, VerificationVersion uint64
	User                                   UserAuthorityAdmission
}

// RequireVerifiedIdentifier fences the original command-bound user's security
// epochs and exact still-verified identifier in the sole protected transaction.
// Primary user then identifier share locks remain until commit/abort. Lookup is
// by original identifier ID, never a newly supplied address; removed, reassigned,
// reverified or stale state denies and poisons live Work even if ignored. The
// canonical address is read only inside its owner and never returned as a new
// authentication or renewable validity lease. No credential row is invented.
func (w Work) RequireVerifiedIdentifier(ctx context.Context, p FeatureExecutionContributor, expected VerifiedIdentifierAdmission) error {
	if w.state == nil || w.state.featureInvocation == nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return w.fail(ctx, invalidWork())
	}
	if !queryScopeText(string(expected.IdentifierID)) || expected.Kind != identity.IdentifierEmail && expected.Kind != identity.IdentifierPhone || expected.IdentifierVersion == 0 || expected.VerificationVersion == 0 {
		return w.fail(ctx, invalidRecipient())
	}
	if err := w.RequireActiveUserAuthority(ctx, p, expected.User); err != nil {
		return err
	}
	rows, err := w.Query(ctx, recipientColumns+` WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3 AND i.kind=$4 LIMIT 2 FOR SHARE OF i`, string(b.TenantID), string(b.UserID), string(expected.IdentifierID), string(expected.Kind))
	if err != nil {
		return w.fail(ctx, err)
	}
	record, err := readRecipientSelection(RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: expected.Kind, Eligibility: RecipientVerified}, rows, true)
	rows.Close()
	if err != nil {
		return w.fail(ctx, readFailure(ctx, err))
	}
	if record.Suppressed || record.Identifier.ID != expected.IdentifierID || record.Identifier.Version != expected.IdentifierVersion || record.Verification.Version != expected.VerificationVersion || record.UserAuthorityVersion != expected.User.UserAuthorityVersion || record.IdentifierAuthorityVersion != expected.User.IdentifierAuthorityVersion || record.CredentialAuthorityVersion != expected.User.CredentialAuthorityVersion {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}

// Format redacts correlated identifier and security versions.
func (VerifiedIdentifierAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.VerifiedIdentifierAdmission(redacted)"))
}

// MarshalJSON rejects accidental admission export.
func (VerifiedIdentifierAdmission) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects accidental admission export.
func (VerifiedIdentifierAdmission) MarshalText() ([]byte, error) { return nil, invalidWork() }
