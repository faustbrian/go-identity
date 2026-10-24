package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func invalidPasskeyCredentialCreation() error {
	return identity.InvalidInputError{Field: "passkey_credential_creation"}
}

// PasskeyCredentialCreationFields binds an initial passkey-owned reference and
// all three original user security epochs into the enrolling native command.
// The returned fields contain no verifier, WebAuthn credential bytes or proof;
// they grant neither enrollment permission nor authentication. Version must be
// one, and each authority must be positive. User aggregate version is not an
// authority epoch. Copies own their scalar values and construction performs no IO.
func PasskeyCredentialCreationFields(c identity.CredentialRef, a UserAuthorityAdmission) ([]identity.FeatureField, error) {
	if c.Validate(c.TenantID, c.UserID) != nil || c.Kind != identity.CredentialPasskey || c.Owner != "passkey" || c.Version != 1 || a.UserAuthorityVersion == 0 || a.IdentifierAuthorityVersion == 0 || a.CredentialAuthorityVersion == 0 {
		return nil, invalidPasskeyCredentialCreation()
	}
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "passkey-reference." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "passkey-reference." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	return []identity.FeatureField{text("id", string(c.ID)), text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("owner", c.Owner), number("kind", uint64(c.Kind)), number("version", c.Version), number("user-authority", a.UserAuthorityVersion), number("identifier-authority", a.IdentifierAuthorityVersion), number("credential-authority", a.CredentialAuthorityVersion)}, nil
}

func passkeyCredentialCreationMatches(s identity.FeatureCommandSpec, c identity.CredentialRef, a UserAuthorityAdmission) bool {
	expected, err := PasskeyCredentialCreationFields(c, a)
	if err != nil || c.TenantID != s.Binding.TenantID || c.UserID != s.Binding.UserID || string(c.ID) != s.Binding.RecordID {
		return false
	}
	matched := make(map[string]bool, len(expected))
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "passkey-reference.") {
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

// CreatePasskeyCredential inserts only the initial non-secret kernel reference
// during the exact registered native passkey enrollment Apply invocation. Bind
// PasskeyCredentialCreationFields unchanged in the original command and install
// CredentialMigrationSource first. The command's record is the new reference,
// its actor is that same existing user and its lifecycle is
// identity.passkey.create_credential at zero-to-one. Session-bound additional
// enrollment selects the exact .session-registration-v1 schema and event index
// zero. The previously supported passkey.registered.v1 name remains admitted
// only for existing .native-v1 composers. No other
// operation, owner, reconstructed command or reference
// replacement is admitted. Existing references, including disabled ones, conflict
// without resurrection; no existing user or credential epoch is incremented.
//
// Current active user and all original user security epochs are locked through
// the sole coordinator Work. Every live rejection poisons Work. The native owner
// must separately verify WebAuthn, original session/fresh proof, factor, directory,
// policy and risk, stage mapping and required effects in this same Work, and repeat
// current reference/admission checks before commit. Success is provisional only;
// it grants no authentication, session, separate commit or recovery authority.
// This method owns no transaction, pool, callback, cache or goroutine.
func (w Work) CreatePasskeyCredential(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, c identity.CredentialRef, a UserAuthorityAdmission) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, feature, lifecycle, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	sessionOperation := op
	sessionOperation.SchemaID = "identity.passkey.register-verify.session-registration-v1"
	if s.Operation == sessionOperation {
		op = sessionOperation
	}
	descriptor := ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
	if err != nil || !ok || s.Binding != b || s.Operation != op || feature.Operation != op || feature.Contributor != descriptor || (lifecycle.EventType != "identity.passkey.create_credential" && lifecycle.EventType != "passkey.registered.v1") || lifecycle.BeforeVersion != 0 || lifecycle.AfterVersion != 1 || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || !passkeyCredentialCreationMatches(s, c, a) {
		return w.fail(ctx, invalidPasskeyCredentialCreation())
	}
	// The new UV-authorized session profile has one canonical lifecycle. Keep
	// the historical alias confined to the existing password-proof profile.
	if op == sessionOperation && lifecycle != (LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}) {
		return w.fail(ctx, invalidPasskeyCredentialCreation())
	}
	if err := w.RequireActiveUserAuthority(ctx, owner, a); err != nil {
		return err
	}
	// Never upsert: an old disabled reference is a denial predecessor, not an
	// invitation to reactivate it. The native protocol owner separately enforces
	// RP-wide cryptographic credential uniqueness without tenant disambiguation.
	n, err := w.Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',1,true) ON CONFLICT(tenant_id,user_id,credential_id) DO NOTHING`, string(c.TenantID), string(c.UserID), string(c.ID))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	return nil
}
