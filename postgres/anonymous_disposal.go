package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// AnonymousDisposalAction selects kernel-owned disposal, not authorization.
// Delete retains an irreversible identity tombstone and minimal non-contact
// creation linkage, but removes attributes/profile. Anonymize does the same
// erasure with a distinct terminal status. Retain preserves those payloads and
// terminalizes authentication only. Unknown/zero values deny.
type AnonymousDisposalAction string

const (
	AnonymousDisposeDelete    AnonymousDisposalAction = "delete"
	AnonymousDisposeAnonymize AnonymousDisposalAction = "anonymize"
	AnonymousDisposeRetain    AnonymousDisposalAction = "retain"
)

// AnonymousDisposalSnapshot preserves the primary kernel's original user,
// placeholder, three independent authority epochs and legal-hold generation.
// It grants no session possession, risk or retention permission. A protected
// disposal compares this whole snapshot again under the existing Work lock.
type AnonymousDisposalSnapshot struct {
	Authority        AnonymousAuthorityRecord
	LegalHold        bool
	LegalHoldVersion uint64
}

// AnonymousDisposalIntent freezes kernel disposal and retention-policy identity
// before command fingerprinting. The workflow must obtain its bounded retention
// decision outside SQL, then fence this original snapshot inside the same Work
// as anonymous state, all anonymous-session revocation, audit and outbox.
type AnonymousDisposalIntent struct {
	Snapshot               AnonymousDisposalSnapshot
	Action                 AnonymousDisposalAction
	RetentionPolicyVersion uint64
}

// AnonymousDisposalDomain borrows the exact enlisted kernel repository. It owns
// all ordinary user/attribute SQL, no pool lifetime, transaction or callback.
// Immutable composition is concurrent-safe; borrowed Work remains serial-use.
type AnonymousDisposalDomain struct{ repository *Repository }

type anonymousDisposalProgress struct {
	before AnonymousDisposalIntent
	after  identity.User
}

func invalidAnonymousDisposal() error { return identity.InvalidInputError{Field: "anonymous_disposal"} }
func anonymousDisposalOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.delete", SchemaID: "identity.anonymous.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewAnonymousDisposalDomain checks explicit owner composition without IO.
// AnonymousDisposalMigrationSource and the complete creation/status histories
// must already be installed; construction performs no automatic migration.
func NewAnonymousDisposalDomain(r *Repository) (*AnonymousDisposalDomain, error) {
	if r == nil || r.pool == nil || r.read == nil {
		return nil, invalidAnonymousDisposal()
	}
	return &AnonymousDisposalDomain{repository: r}, nil
}

func (i AnonymousDisposalIntent) validate() error {
	a := i.Snapshot.Authority
	if a.Validate() != nil || a.User.Status != identity.StatusActive || a.User.Version == ^uint64(0) || a.UserAuthorityVersion == ^uint64(0) || a.IdentifierAuthorityVersion == ^uint64(0) || a.CredentialAuthorityVersion == ^uint64(0) || i.Snapshot.LegalHoldVersion == 0 || i.RetentionPolicyVersion == 0 || (i.Action != AnonymousDisposeDelete && i.Action != AnonymousDisposeAnonymize && i.Action != AnonymousDisposeRetain) || i.Snapshot.LegalHold && i.Action != AnonymousDisposeRetain {
		return invalidAnonymousDisposal()
	}
	return nil
}

// AnonymousDisposalFields binds every original kernel/retention input to the
// command. It is structural mapping only, with no IO or destruction authority.
func AnonymousDisposalFields(i AnonymousDisposalIntent) ([]identity.FeatureField, error) {
	if err := i.validate(); err != nil {
		return nil, err
	}
	a := i.Snapshot.Authority
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.disposal." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	u := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.disposal." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	held := uint64(0)
	if i.Snapshot.LegalHold {
		held = 1
	}
	return []identity.FeatureField{text("user", string(a.User.ID)), text("placeholder", string(a.Placeholder.ID)), text("action", string(i.Action)), u("user-version", a.User.Version), u("user-epoch", a.UserAuthorityVersion), u("identifier-epoch", a.IdentifierAuthorityVersion), u("credential-epoch", a.CredentialAuthorityVersion), u("hold", held), u("hold-version", i.Snapshot.LegalHoldVersion), u("retention-policy", i.RetentionPolicyVersion)}, nil
}

type disposalRows struct {
	anonymousAuthorityRows
	hold        bool
	holdVersion string
}

func (r *disposalRows) Scan(fields ...any) error {
	return r.anonymousAuthorityRows.Scan(append([]any{&r.hold, &r.holdVersion}, fields...)...)
}
func anonymousDisposalSelect() string {
	return strings.Replace(anonymousAuthoritySelect, "SELECT u.tenant_id,", "SELECT u.legal_hold,u.legal_hold_version::text,u.tenant_id,", 1)
}
func readAnonymousDisposal(q identity.UserStatusQuery, rows anonymousAuthorityRows) (AnonymousDisposalSnapshot, error) {
	r := &disposalRows{anonymousAuthorityRows: rows}
	a, err := readAnonymousAuthority(q, r)
	if err != nil {
		return AnonymousDisposalSnapshot{}, err
	}
	v, err := strconv.ParseUint(r.holdVersion, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != r.holdVersion {
		return AnonymousDisposalSnapshot{}, identity.UnavailableError{}
	}
	return AnonymousDisposalSnapshot{Authority: a, LegalHold: r.hold, LegalHoldVersion: v}, nil
}

// GetAnonymousDisposal performs one bounded authoritative read, including legal
// hold and all anonymous ownership checks. Terminal/blocked snapshots remain
// terminal/blocked, never converted to deletion permission. Callers preserve the
// original read-start deadline across session, risk and retention decisions.
func (r *Repository) GetAnonymousDisposal(ctx context.Context, q identity.UserStatusQuery) (AnonymousDisposalSnapshot, error) {
	shape := identity.User{TenantID: q.TenantID, ID: q.UserID, Status: identity.StatusActive, Version: 1}
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || shape.Validate(q.TenantID) != nil {
		return AnonymousDisposalSnapshot{}, invalidAnonymousDisposal()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	rows, err := r.pool.Raw().Query(bounded, anonymousDisposalSelect(), string(q.TenantID), string(q.UserID))
	if err != nil {
		return AnonymousDisposalSnapshot{}, readFailure(bounded, err)
	}
	defer rows.Close()
	s, err := readAnonymousDisposal(q, rows)
	if err != nil {
		return AnonymousDisposalSnapshot{}, readFailure(bounded, err)
	}
	if bounded.Err() != nil {
		return AnonymousDisposalSnapshot{}, readFailure(bounded, bounded.Err())
	}
	return s, nil
}

// Apply fences and disposes only the exact kernel-created anonymous user in the
// current registered delete invocation. Additional contacts/credentials, changed
// authority or legal hold deny before erasure. Errors poison Work even when a
// caller ignores them. Success remains provisional until every owner commits.
func (d *AnonymousDisposalDomain) Apply(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, i AnonymousDisposalIntent) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(ctx, err) }
	if ctx == nil || d == nil || d.repository == nil || i.validate() != nil {
		return fail(invalidAnonymousDisposal())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	b, f, l, err := w.FeatureScope(p)
	if err != nil || p.Descriptor() != anonymousCreationDescriptor() || f.Operation != anonymousDisposalOperation() || b.UserID != i.Snapshot.Authority.User.ID || b.TenantID != i.Snapshot.Authority.User.TenantID || b.RecordID != string(b.UserID) || string(b.ActorID) != string(b.UserID) || l.EventType != "anonymous.deleted.v1" || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 || w.state.anonymousDisposal != nil || w.state.anonymousCreation != nil || w.state.creation != nil || w.state.update != nil || w.state.status != nil || w.state.profile != nil || w.state.identifier != nil {
		return fail(invalidAnonymousDisposal())
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != b || spec.Operation != f.Operation {
		return fail(invalidAnonymousDisposal())
	}
	fields, _ := AnonymousDisposalFields(i)
	matched := 0
	for _, actual := range spec.Fields {
		if !strings.HasPrefix(actual.Name, "anonymous.disposal.") {
			continue
		}
		found := false
		for _, want := range fields {
			if want.Name != actual.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			v, ev := encodeFeatureValue(want.Value)
			if ea != nil || ev != nil || !bytes.Equal(a, v) {
				return fail(invalidAnonymousDisposal())
			}
			matched++
			found = true
			break
		}
		if !found {
			return fail(invalidAnonymousDisposal())
		}
	}
	if matched != len(fields) {
		return fail(invalidAnonymousDisposal())
	}
	enlisted := false
	for _, e := range w.state.execution.reservation.plan.contributors {
		if e.descriptor.Owner == "identity/postgres" && e.contributor == d.repository {
			enlisted = true
		}
	}
	if !enlisted {
		return fail(invalidWork())
	}
	rows, err := w.Query(ctx, anonymousDisposalSelect()+" FOR UPDATE OF u,i", string(b.TenantID), string(b.UserID))
	if err != nil {
		return identity.User{}, err
	}
	current, err := readAnonymousDisposal(identity.UserStatusQuery{TenantID: b.TenantID, UserID: b.UserID}, rows)
	rows.Close()
	if err != nil || current != i.Snapshot {
		return fail(identity.ForbiddenError{})
	}
	u := current.Authority.User
	u.Version++
	u.Status = identity.StatusDeleted
	if i.Action == AnonymousDisposeAnonymize {
		u.Status = identity.StatusAnonymized
	}
	// A retained tombstone prevents revival/import collisions and preserves the
	// original command/audit foreign keys. Physical payload erasure is bounded
	// to these kernel-owned single-user rows; anonymous/session owners dispose
	// their own state inside this same Work, never through a later callback.
	n, err := w.Exec(ctx, `UPDATE identity.users SET status=$3,version=version+1,authority_version=authority_version+1,identifier_version=identifier_version+1,credential_version=credential_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$4::numeric AND legal_hold_version=$5::numeric`, string(b.TenantID), string(b.UserID), string(u.Status), strconv.FormatUint(current.Authority.User.Version, 10), strconv.FormatUint(current.LegalHoldVersion, 10))
	if err != nil {
		return identity.User{}, err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	if i.Action != AnonymousDisposeRetain {
		for _, table := range []string{"identity.user_attributes", "identity.user_profiles"} {
			if _, err := w.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); err != nil {
				return identity.User{}, err
			}
		}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return fail(invalidAnonymousDisposal())
	}
	n, err = w.Exec(ctx, `INSERT INTO identity.anonymous_disposals(tenant_id,purpose,command_id,user_id,action,before_version,after_version,before_user_version,before_authority_version,before_identifier_version,before_credential_version,legal_hold,legal_hold_version,retention_policy_version) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9::numeric,$10::numeric,$11::numeric,$12,$13::numeric,$14::numeric)`, string(b.TenantID), b.OperationID, id, string(b.UserID), string(i.Action), strconv.FormatUint(l.BeforeVersion, 10), strconv.FormatUint(l.AfterVersion, 10), strconv.FormatUint(current.Authority.User.Version, 10), strconv.FormatUint(current.Authority.UserAuthorityVersion, 10), strconv.FormatUint(current.Authority.IdentifierAuthorityVersion, 10), strconv.FormatUint(current.Authority.CredentialAuthorityVersion, 10), current.LegalHold, strconv.FormatUint(current.LegalHoldVersion, 10), strconv.FormatUint(i.RetentionPolicyVersion, 10))
	if err != nil {
		return identity.User{}, err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	w.state.anonymousDisposal = &anonymousDisposalProgress{before: i, after: u}
	return u, nil
}

// AnonymousDisposal reads the actual provisional kernel disposal during this
// exact delete participant's Apply invocation. It cannot be supplied by a caller
// as permanent-user mutation or authentication evidence, and expires with Work.
func (w Work) AnonymousDisposal(p FeatureExecutionContributor) (identity.User, error) {
	b, f, _, err := w.FeatureScope(p)
	if err != nil || p.Descriptor() != anonymousCreationDescriptor() || f.Operation != anonymousDisposalOperation() || !w.state.featureApplying || w.state.anonymousDisposal == nil {
		return identity.User{}, invalidWork()
	}
	u := w.state.anonymousDisposal.after
	if u.TenantID != b.TenantID || u.ID != b.UserID {
		return identity.User{}, invalidWork()
	}
	return u, nil
}

// Check repeats the exact applied terminal kernel state and original legal hold
// during the coordinator's final read-only fence. It neither erases payload nor
// renews an admission deadline. The workflow separately fences its original
// session, anonymous transition, risk and retention decision.
func (d *AnonymousDisposalDomain) Check(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, i AnonymousDisposalIntent) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil || d == nil || d.repository == nil || i.validate() != nil {
		return w.fail(ctx, invalidAnonymousDisposal())
	}
	if w.state.featureApplying || w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return w.fail(ctx, invalidWork())
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil || f.Operation != anonymousDisposalOperation() || p.Descriptor() != anonymousCreationDescriptor() || w.state.anonymousDisposal == nil || w.state.anonymousDisposal.before != i || b.TenantID != i.Snapshot.Authority.User.TenantID || b.UserID != i.Snapshot.Authority.User.ID {
		return w.fail(ctx, invalidAnonymousDisposal())
	}
	want := i.Snapshot
	want.Authority.User = w.state.anonymousDisposal.after
	want.Authority.UserAuthorityVersion++
	want.Authority.IdentifierAuthorityVersion++
	want.Authority.CredentialAuthorityVersion++
	rows, err := w.Query(ctx, anonymousDisposalSelect()+" FOR SHARE OF u,i", string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	got, err := readAnonymousDisposal(identity.UserStatusQuery{TenantID: b.TenantID, UserID: b.UserID}, rows)
	rows.Close()
	if err != nil || got != want {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}

func recoverAnonymousDisposal(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || w.state.plan.feature == nil || w.state.plan.feature.Operation != anonymousDisposalOperation() || w.state.plan.lifecycle == nil {
		return RecoveryUnknown, invalidAnonymousDisposal()
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return RecoveryUnknown, invalidAnonymousDisposal()
	}
	l := w.state.plan.lifecycle
	rows, err := w.Query(ctx, `SELECT user_id,before_version::text,after_version::text FROM identity.anonymous_disposals WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return RecoveryUnknown, err
		}
		return RecoveryNotCommitted, nil
	}
	var user, before, after string
	if err := rows.Scan(&user, &before, &after); err != nil {
		return RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil || user != string(b.UserID) || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	return RecoveryCommitted, nil
}

func (AnonymousDisposalIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousDisposalIntent(redacted)"))
}
func (AnonymousDisposalSnapshot) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousDisposalSnapshot(redacted)"))
}
func (AnonymousDisposalDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousDisposalDomain(redacted)"))
}
func (AnonymousDisposalIntent) MarshalJSON() ([]byte, error) { return nil, invalidAnonymousDisposal() }
func (AnonymousDisposalSnapshot) MarshalJSON() ([]byte, error) {
	return nil, invalidAnonymousDisposal()
}
func (AnonymousDisposalDomain) MarshalJSON() ([]byte, error) { return nil, invalidAnonymousDisposal() }
