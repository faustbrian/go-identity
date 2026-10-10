package postgres

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// PasswordHashUpgradeIntent freezes independent predecessor versions for a
// hash-only upgrade inside the original password-signin command. It contains
// no hash, password, proof or grant. The native password owner must verify the
// original bytes and prepare bounded replacement material before opening Work.
// User aggregate, security epochs and credential record versions are distinct.
type PasswordHashUpgradeIntent struct {
	Admission           CredentialAdmission
	ExpectedUserVersion uint64
}

// PasswordHashUpgradeReceipt is provisional kernel-owned successor metadata.
// Only the original signin journal's committed outcome proves durability.
// Advancing credential authority invalidates predecessor-bound sessions; this
// receipt cannot preserve them, grant a session or renew any validity evidence.
type PasswordHashUpgradeReceipt struct {
	CommandID                                     identity.CommandID
	Credential                                    identity.CredentialRef
	BeforeUserVersion, AfterUserVersion           uint64
	BeforeAuthorityVersion, AfterAuthorityVersion uint64
	BeforeCredentialVersion                       uint64
}

// Format redacts predecessor metadata for every formatting verb.
func (PasswordHashUpgradeIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasswordHashUpgradeIntent(redacted)")
}

// MarshalJSON refuses general-purpose serialization of transaction metadata.
func (PasswordHashUpgradeIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidPasswordHashUpgrade()
}

// MarshalText refuses general-purpose serialization of transaction metadata.
func (PasswordHashUpgradeIntent) MarshalText() ([]byte, error) {
	return nil, invalidPasswordHashUpgrade()
}

// Format redacts provisional successor metadata for every formatting verb.
func (PasswordHashUpgradeReceipt) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasswordHashUpgradeReceipt(redacted)")
}

// MarshalJSON refuses to export provisional transaction metadata.
func (PasswordHashUpgradeReceipt) MarshalJSON() ([]byte, error) {
	return nil, invalidPasswordHashUpgrade()
}

// MarshalText refuses to export provisional transaction metadata.
func (PasswordHashUpgradeReceipt) MarshalText() ([]byte, error) {
	return nil, invalidPasswordHashUpgrade()
}

type passwordHashUpgradeState struct {
	intent    PasswordHashUpgradeIntent
	recipient RecipientRecord
	receipt   *PasswordHashUpgradeReceipt
}

func invalidPasswordHashUpgrade() error {
	return identity.InvalidInputError{Field: "password_hash_upgrade"}
}

// PasswordHashUpgradeFields returns the complete owned predecessor projection.
// Include every field unchanged in the original paired signin command before
// fingerprinting. Returned fields do not alias intent. No IO or callbacks run;
// this mapping grants no authentication or permission to mutate a credential.
func PasswordHashUpgradeFields(s PasswordHashUpgradeIntent) ([]identity.FeatureField, error) {
	a, c := s.Admission, s.Admission.Credential
	if c.Kind != identity.CredentialPassword || c.Owner != "identity/password" || c.Validate(c.TenantID, c.UserID) != nil || c.Version == ^uint64(0) || s.ExpectedUserVersion == 0 || s.ExpectedUserVersion == ^uint64(0) || a.CredentialAuthorityVersion == 0 || a.CredentialAuthorityVersion == ^uint64(0) || a.UserAuthorityVersion == 0 || a.IdentifierAuthorityVersion == 0 {
		return nil, invalidPasswordHashUpgrade()
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "password.upgrade." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "password.upgrade." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{text("id", string(c.ID)), text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("owner", c.Owner), number("kind", uint64(c.Kind)), number("version", c.Version), number("user-version", s.ExpectedUserVersion), number("user-authority", a.UserAuthorityVersion), number("identifier-authority", a.IdentifierAuthorityVersion), number("credential-authority", a.CredentialAuthorityVersion)}, nil
}

func decodePasswordHashUpgrade(s identity.FeatureCommandSpec) (PasswordHashUpgradeIntent, error) {
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if s.Binding.AnonymousFlowID != "" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	if s.Operation != op || s.Binding.OperationID != op.OperationID || s.Binding.SchemaID != op.SchemaID || s.Binding.SchemaVersion != op.SchemaVersion || s.Binding.RecordID != "" {
		return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
	}
	values := make(map[string]identity.FeatureValue, 10)
	for _, f := range s.Fields {
		if !strings.HasPrefix(f.Name, "password.upgrade.") {
			continue
		}
		if _, duplicate := values[f.Name]; duplicate {
			return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
		}
		values[f.Name] = f.Value
	}
	if len(values) != 10 {
		return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
	}
	v := func(n string) identity.FeatureValue { return values["password.upgrade."+n] }
	intent := PasswordHashUpgradeIntent{Admission: CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(v("id").Text), TenantID: identity.TenantID(v("tenant").Text), UserID: identity.UserID(v("user").Text), Kind: identity.CredentialPassword, Owner: v("owner").Text, Version: v("version").Uint64}, UserAuthorityVersion: v("user-authority").Uint64, IdentifierAuthorityVersion: v("identifier-authority").Uint64, CredentialAuthorityVersion: v("credential-authority").Uint64}, ExpectedUserVersion: v("user-version").Uint64}
	expected, err := PasswordHashUpgradeFields(intent)
	if err != nil || intent.Admission.Credential.TenantID != s.Binding.TenantID || s.Binding.UserID != "" && s.Binding.UserID != intent.Admission.Credential.UserID {
		return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
	}
	for _, f := range expected {
		value, ok := values[f.Name]
		if !ok || value.Kind != f.Value.Kind || value.Text != f.Value.Text || value.Uint64 != f.Value.Uint64 || value.Int64 != 0 || value.Bool || value.Bytes != nil || value.Time != (time.Time{}) {
			return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
		}
	}
	return intent, nil
}

func (w Work) passwordUpgradeCommand(p FeatureExecutionContributor, c identity.Command) (PasswordHashUpgradeIntent, error) {
	b, f, l, err := w.FeatureScope(p)
	if err != nil || !w.state.featureApplying || w.state.featureApplyCommand == nil || *w.state.featureApplyCommand != c || p.Descriptor() != (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || l.EventType != "session.created.v1" || l.BeforeVersion != 0 || l.AfterVersion != 0 {
		return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
	}
	s, ok := c.PasswordSigninFeature()
	secret, _, custody := c.PasswordSigninCustody()
	if !ok || !custody || secret.Len() == 0 || s.Binding != b || s.Operation != f.Operation {
		return PasswordHashUpgradeIntent{}, invalidPasswordHashUpgrade()
	}
	return decodePasswordHashUpgrade(s)
}

// PreparePasswordHashUpgrade exclusively locks the original selected user and
// credential before identifier admission. Call after directory admission and
// before any shared user/credential admission, preventing lock-upgrade races.
// Only the exact registered native password owner's active Apply invocation
// and original paired command may use it. The frozen predecessors, recipient,
// status, expiry and independent epochs must agree. Anonymous scope stays intact.
// Denials poison Work. It neither writes material nor authenticates a password.
func (w Work) PreparePasswordHashUpgrade(ctx context.Context, p FeatureExecutionContributor, command identity.Command, recipient RecipientRecord) error {
	if w.usable() != nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidPasswordHashUpgrade())
	}
	intent, err := w.passwordUpgradeCommand(p, command)
	a := intent.Admission
	if err != nil || w.state.passwordUpgrade != nil || recipient.Validate() != nil || recipient.Suppressed || recipient.User.ID != a.Credential.UserID || recipient.User.Version != intent.ExpectedUserVersion || recipient.UserAuthorityVersion != a.UserAuthorityVersion || recipient.IdentifierAuthorityVersion != a.IdentifierAuthorityVersion || recipient.CredentialAuthorityVersion != a.CredentialAuthorityVersion {
		return w.fail(ctx, invalidPasswordHashUpgrade())
	}
	b := w.state.binding
	b.UserID = a.Credential.UserID
	if _, err := w.requireActiveCredentialLock(ctx, b, a, true, intent.ExpectedUserVersion); err != nil {
		// Low-level cursor misuse can reject a read without poisoning Work.
		// Upgrade admission must remain terminal even if its caller ignores it.
		return w.fail(ctx, err)
	}
	if err := w.RequireRecipient(ctx, p, recipient); err != nil {
		return err
	}
	w.state.passwordUpgrade = &passwordHashUpgradeState{intent: intent, recipient: recipient}
	return nil
}

// ApplyPasswordHashUpgrade advances only kernel-owned reference, aggregate and
// credential-authority versions in this Work after native material CAS succeeds.
// The caller must abort on any material error and must bind the successor into
// its signed signin record and session before returning. No password-change
// command, second transaction, journal, timestamp renewal or session is created.
// Repeated, substituted, unprepared or post-invocation use denies and poisons
// Work. Returned metadata is provisional; the coordinator alone may commit.
func (w Work) ApplyPasswordHashUpgrade(ctx context.Context, p FeatureExecutionContributor, command identity.Command) (PasswordHashUpgradeReceipt, error) {
	if w.usable() != nil {
		return PasswordHashUpgradeReceipt{}, invalidWork()
	}
	if ctx == nil {
		return PasswordHashUpgradeReceipt{}, w.fail(w.state.ctx, invalidPasswordHashUpgrade())
	}
	intent, err := w.passwordUpgradeCommand(p, command)
	state := w.state.passwordUpgrade
	if err != nil || state == nil || state.receipt != nil || state.intent != intent {
		return PasswordHashUpgradeReceipt{}, w.fail(ctx, invalidPasswordHashUpgrade())
	}
	a, c := intent.Admission, intent.Admission.Credential
	number := func(v uint64) string { return strconv.FormatUint(v, 10) }
	n, err := w.Exec(ctx, `UPDATE identity.users SET version=version+1,credential_version=credential_version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND credential_version=$4::numeric AND authority_version=$5::numeric AND identifier_version=$6::numeric AND status='active'`, string(c.TenantID), string(c.UserID), number(intent.ExpectedUserVersion), number(a.CredentialAuthorityVersion), number(a.UserAuthorityVersion), number(a.IdentifierAuthorityVersion))
	if err != nil {
		return PasswordHashUpgradeReceipt{}, err
	}
	if n != 1 {
		return PasswordHashUpgradeReceipt{}, w.fail(ctx, identity.ConflictError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity.credential_references SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND kind=1 AND owner='identity/password' AND version=$4::numeric AND enabled=true AND (expires_at IS NULL OR expires_at>clock_timestamp())`, string(c.TenantID), string(c.UserID), string(c.ID), number(c.Version))
	if err != nil {
		return PasswordHashUpgradeReceipt{}, err
	}
	if n != 1 {
		return PasswordHashUpgradeReceipt{}, w.fail(ctx, identity.ConflictError{})
	}
	before := c.Version
	c.Version++
	r := PasswordHashUpgradeReceipt{CommandID: w.state.binding.CommandID, Credential: c, BeforeUserVersion: intent.ExpectedUserVersion, AfterUserVersion: intent.ExpectedUserVersion + 1, BeforeAuthorityVersion: a.CredentialAuthorityVersion, AfterAuthorityVersion: a.CredentialAuthorityVersion + 1, BeforeCredentialVersion: before}
	state.receipt = &r
	return r, nil
}

// PasswordHashUpgradeSuccessor returns scalar owner-derived successor admission
// during the exact native Apply invocation. Original observation time, user and
// identifier security epochs, verification and expiry are unchanged. This is
// not freshly read authority or a renewable lease. Session's owner must fence
// this exact successor before issuance; zero/unapplied/foreign Work denies.
func (w Work) PasswordHashUpgradeSuccessor(p FeatureExecutionContributor) (RecipientRecord, CredentialAdmission, error) {
	if _, _, _, err := w.FeatureCommandIdentity(p); err != nil || w.state.passwordUpgrade == nil || w.state.passwordUpgrade.receipt == nil {
		return RecipientRecord{}, CredentialAdmission{}, invalidWork()
	}
	s := w.state.passwordUpgrade
	r, a := s.recipient, s.intent.Admission
	r.User.Version = s.receipt.AfterUserVersion
	r.CredentialAuthorityVersion = s.receipt.AfterAuthorityVersion
	a.Credential, a.CredentialAuthorityVersion = s.receipt.Credential, s.receipt.AfterAuthorityVersion
	return r, a, nil
}

// StagedPasswordHashUpgrade exposes provisional metadata to the registered
// lifecycle participant after feature application. It grants no authority and
// cannot reconstruct history from mutable rows. A missing upgrade, unusable
// Work or unstaged lifecycle denies; original journal remains outcome owner.
func (w Work) StagedPasswordHashUpgrade() (PasswordHashUpgradeReceipt, error) {
	if w.usable() != nil || w.state.passwordUpgrade == nil || w.state.passwordUpgrade.receipt == nil || w.state.lifecycle == nil || w.state.lifecycle.record == nil {
		return PasswordHashUpgradeReceipt{}, invalidWork()
	}
	return *w.state.passwordUpgrade.receipt, nil
}

func (w Work) checkPasswordHashUpgradeFinal() error {
	s := w.state.passwordUpgrade
	if s == nil {
		return nil
	}
	if s.receipt == nil {
		return w.fail(w.state.ctx, invalidPasswordHashUpgrade())
	}
	b := w.state.binding
	b.UserID = s.receipt.Credential.UserID
	a := s.intent.Admission
	a.Credential, a.CredentialAuthorityVersion = s.receipt.Credential, s.receipt.AfterAuthorityVersion
	_, err := w.requireActiveCredentialLock(w.state.ctx, b, a, false, s.receipt.AfterUserVersion)
	return err
}
