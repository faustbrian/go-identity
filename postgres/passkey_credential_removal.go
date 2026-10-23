package postgres

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func invalidPasskeyCredentialRemoval() error {
	return identity.InvalidInputError{Field: "passkey_credential_removal"}
}

// PasskeyCredentialRemovalFields binds an existing passkey reference and all
// three independent user security epochs to the original removal command.
// Version must be positive and have a representable successor. The fields
// contain neither protocol bytes nor authentication/recovery permission.
// Construction owns its scalar values, performs no IO and is concurrency-safe.
func PasskeyCredentialRemovalFields(c identity.CredentialRef, a UserAuthorityAdmission) ([]identity.FeatureField, error) {
	if c.Validate(c.TenantID, c.UserID) != nil || c.Kind != identity.CredentialPasskey || c.Owner != "passkey" || c.Version == ^uint64(0) || a.UserAuthorityVersion == 0 || a.IdentifierAuthorityVersion == 0 || a.CredentialAuthorityVersion == 0 {
		return nil, invalidPasskeyCredentialRemoval()
	}
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "passkey-removal-reference." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "passkey-removal-reference." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	return []identity.FeatureField{text("id", string(c.ID)), text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("owner", c.Owner), number("kind", uint64(c.Kind)), number("version", c.Version), number("user-authority", a.UserAuthorityVersion), number("identifier-authority", a.IdentifierAuthorityVersion), number("credential-authority", a.CredentialAuthorityVersion)}, nil
}

func passkeyCredentialRemovalMatches(s identity.FeatureCommandSpec, c identity.CredentialRef, a UserAuthorityAdmission) bool {
	expected, err := PasskeyCredentialRemovalFields(c, a)
	if err != nil || c.TenantID != s.Binding.TenantID || c.UserID != s.Binding.UserID || string(c.ID) != s.Binding.RecordID {
		return false
	}
	matched := make(map[string]bool, len(expected))
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "passkey-removal-reference.") {
			continue
		}
		found := false
		for _, field := range expected {
			if actual.Name != field.Name {
				continue
			}
			v, want := actual.Value, field.Value
			if matched[field.Name] || v.Kind != want.Kind || v.Text != want.Text || v.Uint64 != want.Uint64 || v.Int64 != 0 || v.Bool || v.Bytes != nil || v.Time != (time.Time{}) {
				return false
			}
			matched[field.Name], found = true, true
			break
		}
		if !found {
			return false
		}
	}
	return len(matched) == len(expected)
}

type passkeyCredentialRemovalProgress struct {
	owner      FeatureExecutionContributor
	command    identity.Command
	credential identity.CredentialRef
	authority  UserAuthorityAdmission
}

func (w Work) requirePasskeyRemovalScope(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, c identity.CredentialRef, a UserAuthorityAdmission) error {
	if w.state == nil {
		return invalidPasskeyCredentialRemoval()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidPasskeyCredentialRemoval())
	}
	b, feature, lifecycle, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	descriptor := ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
	if err != nil || !ok || s.Binding != b || s.Operation != op || feature.Operation != op || feature.Contributor != descriptor || lifecycle.EventType != "identity.passkey.remove_credential" || lifecycle.BeforeVersion != c.Version || lifecycle.AfterVersion != c.Version+1 || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || !passkeyCredentialRemovalMatches(s, c, a) {
		return w.fail(ctx, invalidPasskeyCredentialRemoval())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	return nil
}

// RemovePasskeyCredential disables and advances only the exact original
// passkey reference during its registered native Apply invocation. The original
// command must bind PasskeyCredentialRemovalFields and the canonical removal
// lifecycle. Primary user/reference locks, original epochs and current expiry
// are fenced through the sole coordinator Work; every live rejection poisons it.
// Disabled references remain reserved and cannot be removed twice or restored.
//
// User-wide credential epochs are unchanged: removing one passkey must not
// revoke the independent password session needed for original-key recovery.
// The native owner must separately prove fresh authentication, usable recovery,
// current policy/factors/risk, atomic protocol/mapping removal and passkey
// authority advancement. It must call CheckRemovedPasskeyCredential before
// commit. No transaction, callback, cache or goroutine is created or retained.
func (w Work) RemovePasskeyCredential(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, c identity.CredentialRef, a UserAuthorityAdmission) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := w.requirePasskeyRemovalScope(ctx, owner, command, c, a); err != nil {
		return err
	}
	if w.state.passkeyRemoval != nil {
		return w.fail(ctx, identity.ConflictError{})
	}
	b, _, _, _ := w.FeatureScope(owner)
	admission := CredentialAdmission{Credential: c, UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}
	if _, err := w.requireActiveCredentialLock(ctx, b, admission, true, 0); err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.credential_references SET enabled=false,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND kind=2 AND owner='passkey' AND version=$4::numeric AND enabled=true`, string(c.TenantID), string(c.UserID), string(c.ID), strconv.FormatUint(c.Version, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	w.state.passkeyRemoval = &passkeyCredentialRemovalProgress{owner: owner, command: command, credential: c, authority: a}
	return nil
}

// CheckRemovedPasskeyCredential checks the exact provisional disabled successor
// and unchanged user epochs in this same participant's final invocation. A
// current disabled row without this Work's successful original removal is not
// proof. It performs bounded primary reads only, owns no resources beyond its
// closed cursor and returns redacted errors that poison live Work on rejection.
func (w Work) CheckRemovedPasskeyCredential(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, c identity.CredentialRef, a UserAuthorityAdmission) error {
	if err := w.requirePasskeyRemovalScope(ctx, owner, command, c, a); err != nil {
		return err
	}
	p := w.state.passkeyRemoval
	if p == nil || !sameParticipant(p.owner, owner) || p.command != command || p.credential != c || p.authority != a {
		return w.fail(ctx, invalidPasskeyCredentialRemoval())
	}
	if err := w.RequireActiveUserAuthority(ctx, owner, a); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT version::text,enabled,kind,owner FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 FOR SHARE`, string(c.TenantID), string(c.UserID), string(c.ID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var version, owned string
	var enabled bool
	var kind int16
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return w.fail(ctx, err)
		}
		return w.fail(ctx, identity.ConflictError{})
	}
	if err := rows.Scan(&version, &enabled, &kind, &owned); err != nil {
		return w.fail(ctx, err)
	}
	if rows.Next() || rows.Err() != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if enabled || kind != int16(identity.CredentialPasskey) || owned != c.Owner || version != strconv.FormatUint(c.Version+1, 10) {
		return w.fail(ctx, identity.ConflictError{})
	}
	return w.finishPasskeyRemovalCheck(ctx)
}

// The caller may use a shorter context than Work. A cancellation first
// observed after the final cursor closes must still invalidate the mutation.
func (w Work) finishPasskeyRemovalCheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	return nil
}
