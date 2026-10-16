package postgres

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// EmailRemovalIntent freezes exact removal predecessors and explicit primary
// disposition. Reason is an owner-allowlisted code, not arbitrary audit text.
// It grants no authorization or claim of surviving credential/recovery paths.
type EmailRemovalIntent struct {
	Change                 identity.IdentifierChange
	ComparisonProfile      string
	Reason                 string
	LeavePrimaryUnassigned bool
	// ReplacementPrimary is omitted from legacy original custody when zero.
	// A selected value is independent exact intent, never an inferred successor.
	ReplacementPrimary identity.IdentifierPrimarySelection `json:",omitzero"`
	// Administration is nonzero only for a distinct human actor. It binds the
	// original directory epochs used before canonical actor/target row locks.
	// This is not an authorization decision or authentication proof.
	Administration EmailRemovalAdministration `json:",omitzero"`
}

// EmailRemovalAdministration preserves original directory scope/epochs for
// explicitly administrative removal. Tenant comes from Change/CommandBinding;
// actor comes only from immutable ActorID. Zero retains the legacy self profile.
// The entire value must be frozen in EmailRemovalFields and retained custody.
type EmailRemovalAdministration struct {
	GlobalAuthorityID            string
	GlobalVersion, TenantVersion uint64
}

func (a EmailRemovalAdministration) directory(tenant identity.TenantID) DirectoryAuthorityAdmission {
	return DirectoryAuthorityAdmission{Query: DirectoryAuthorityQuery{GlobalAuthorityID: a.GlobalAuthorityID, TenantID: tenant}, GlobalVersion: a.GlobalVersion, TenantVersion: a.TenantVersion}
}

func (a EmailRemovalAdministration) valid(tenant identity.TenantID) bool {
	return a.directory(tenant).Query.Validate() == nil && a.GlobalVersion != 0 && a.TenantVersion != 0
}

// EmailRemovalContributor supplies immutable removal intent and the existing
// enlisted directory domain. ApplyFeature owns original primary proof, current
// factor/risk admission, actual surviving signin/reset eligibility and exact-
// target capability retirement. Only the kernel writes directory rows. Final
// authority checks and recovery must use the original generation and deadline.
type EmailRemovalContributor interface {
	FeatureCommitContributor
	EmailRemoval(identity.Command) (EmailRemovalIntent, *EmailRemovalDomain, error)
}

// EmailRemovalDomainConfig selects the existing directory writer/reuse keys and
// exact immutable cascade policy. Native command fingerprints must bind this
// complete configuration. ReuseCooldown is microsecond-exact and within 0..365d;
// zero explicitly permits immediate canonical-value reuse, never ID resurrection.
type EmailRemovalDomainConfig struct {
	Directory     EmailAttachmentDomainConfig
	ReuseCooldown time.Duration
	Cascade       IdentifierRemovalCascadeConfig
}

// EmailRemovalDomain lends the enlisted directory's writer and copied policy.
// It owns no pool, transaction, journal, callbacks, workers or consumer closure.
type EmailRemovalDomain struct {
	directory *EmailAttachmentDomain
	cascade   *identifierRemovalCascadePolicy
}

// NewEmailRemovalDomain freezes native composition without IO. The existing
// retirement/status and identifier-removal-cascade migrations must be installed
// before use. Missing consumer contracts deny, not weaken the selected manifest.
func NewEmailRemovalDomain(r *Repository, c EmailRemovalDomainConfig) (*EmailRemovalDomain, error) {
	directory, err := NewEmailAttachmentDomain(r, c.Directory)
	if err != nil {
		return nil, err
	}
	directory.reuse.reuseCooldown = c.ReuseCooldown
	if !directory.reuse.valid() {
		return nil, invalidEmailRemoval()
	}
	cascade, err := freezeIdentifierRemovalCascade(c.Cascade)
	if err != nil {
		return nil, err
	}
	return &EmailRemovalDomain{directory: directory, cascade: cascade}, nil
}

func invalidEmailRemoval() error { return identity.InvalidInputError{Field: "email_removal"} }

func emailRemovalOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.address-remove", SchemaID: "identity.email.address-remove.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// EmailRemovalFields returns all kernel-owned original intent for command
// fingerprinting. No IO, normalization, proof authentication or mutation occurs.
func EmailRemovalFields(i EmailRemovalIntent) ([]identity.FeatureField, error) {
	c := i.Change
	if _, err := identity.IdentifierIntentDigest(c); err != nil || c.Action != identity.IdentifierRemove || c.ExpectedUserVersion == 0 || c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == 0 || c.ExpectedAuthorityVersion == ^uint64(0) || len(i.Reason) > 64 || !featureEventName(i.Reason) {
		return nil, invalidEmailRemoval()
	}
	if _, err := identity.ParseIdentifierID(i.ComparisonProfile); err != nil {
		return nil, invalidEmailRemoval()
	}
	if i.ReplacementPrimary != (identity.IdentifierPrimarySelection{}) && (i.LeavePrimaryUnassigned || i.ReplacementPrimary.Validate() != nil || i.ReplacementPrimary.ID == c.ID) {
		return nil, invalidEmailRemoval()
	}
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "email-removal." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "email-removal." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	fields := []identity.FeatureField{
		text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)),
		text("comparison-profile", i.ComparisonProfile), text("reason", i.Reason),
		number("user-version", c.ExpectedUserVersion), number("authority-version", c.ExpectedAuthorityVersion),
		number("identifier-version", c.ExpectedIdentifierVersion), number("verification-version", c.ExpectedVerificationVersion),
		{Name: "email-removal.leave-primary-unassigned", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: i.LeavePrimaryUnassigned}},
	}
	if i.ReplacementPrimary != (identity.IdentifierPrimarySelection{}) {
		fields = append(fields, text("replacement-identifier", string(i.ReplacementPrimary.ID)), number("replacement-identifier-version", i.ReplacementPrimary.ExpectedIdentifierVersion), number("replacement-verification-version", i.ReplacementPrimary.ExpectedVerificationVersion))
	}
	if i.Administration != (EmailRemovalAdministration{}) {
		if !i.Administration.valid(c.TenantID) {
			return nil, invalidEmailRemoval()
		}
		fields = append(fields, text("actor-global", i.Administration.GlobalAuthorityID), number("actor-global-version", i.Administration.GlobalVersion), number("actor-tenant-version", i.Administration.TenantVersion))
	}
	return fields, nil
}

func emailRemovalCommand(p EmailRemovalContributor, c identity.Command, plan CommandPlan) (EmailRemovalIntent, *EmailRemovalDomain, error) {
	s, ok := commandFeature(c)
	if !ok || s.Operation != emailRemovalOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || plan.SubjectType != "identifier" || plan.Capability != nil || plan.OTP != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.removed.v1" || s.Binding.ActorKind != authorization.SubjectUser || len(plan.Audits) == 0 {
		return EmailRemovalIntent{}, nil, invalidEmailRemoval()
	}
	if _, present := c.SessionToken(); !present {
		return EmailRemovalIntent{}, nil, invalidEmailRemoval()
	}
	for _, a := range plan.Audits {
		if !a.Required || a.RetentionClass != "protected" {
			return EmailRemovalIntent{}, nil, invalidEmailRemoval()
		}
	}
	i, d, err := p.EmailRemoval(c)
	if err != nil || d == nil || d.directory == nil || d.directory.repository == nil || !d.directory.reuse.valid() || d.cascade == nil || !slices.Contains(d.cascade.config.Reasons, i.Reason) || d.directory.comparison != i.ComparisonProfile || i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID || string(i.Change.ID) != s.Binding.RecordID || plan.Lifecycle.BeforeVersion != i.Change.ExpectedIdentifierVersion || plan.Lifecycle.AfterVersion != i.Change.ExpectedIdentifierVersion+1 {
		return EmailRemovalIntent{}, nil, invalidEmailRemoval()
	}
	administrative := string(s.Binding.ActorID) != string(s.Binding.UserID)
	if administrative != (i.Administration != (EmailRemovalAdministration{})) || administrative && !i.Administration.valid(s.Binding.TenantID) {
		return EmailRemovalIntent{}, nil, invalidEmailRemoval()
	}
	fields, err := EmailRemovalFields(i)
	if err != nil {
		return EmailRemovalIntent{}, nil, err
	}
	matched := 0
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "email-removal.") {
			continue
		}
		found := false
		for _, expected := range fields {
			if expected.Name != actual.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if ea != nil || eb != nil || !bytes.Equal(a, b) {
				return EmailRemovalIntent{}, nil, invalidEmailRemoval()
			}
			found, matched = true, matched+1
			break
		}
		if !found {
			return EmailRemovalIntent{}, nil, invalidEmailRemoval()
		}
	}
	if matched != len(fields) {
		return EmailRemovalIntent{}, nil, invalidEmailRemoval()
	}
	return i, d, nil
}

type emailRemovalProgress struct {
	intent   EmailRemovalIntent
	domain   *EmailRemovalDomain
	before   identity.IdentifierState
	mutation identity.IdentifierMutation
	at       time.Time
	applied  bool
	cascade  *identity.LifecycleCascadeAdmission
}

// EmailRemovalScope returns exact command correlation only during the original
// native Apply invocation after the kernel has locked the complete directory
// partition and prepared a safe removal. Capability-owned target retirement
// uses this seam before directory writes. It performs no IO, consumes nothing
// and grants no SQL/transaction ownership. Foreign, reconstructed, unprepared,
// already-applied and returned handles deny; no caller callback is invoked.
func (w Work) EmailRemovalScope(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (identity.CommandBinding, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.CommandBinding{}, err
	}
	b, f, _, err := w.FeatureScope(owner)
	p := w.state.emailRemoval
	if err != nil || f.Operation != emailRemovalOperation() || f.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || p == nil || p.applied || p.intent.Change.Action != identity.IdentifierRemove || p.intent.Change.TenantID != b.TenantID || p.intent.Change.UserID != b.UserID || string(p.intent.Change.ID) != b.RecordID {
		return identity.CommandBinding{}, w.fail(ctx, invalidEmailRemoval())
	}
	return b, nil
}

func prepareEmailRemoval(ctx context.Context, w Work, c identity.Command) error {
	plan := w.state.execution.reservation.plan
	var phase EmailRemovalContributor
	var repo *Repository
	for _, entry := range plan.contributors {
		if entry.descriptor == plan.feature.Contributor {
			phase, _ = entry.contributor.(EmailRemovalContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repo, _ = entry.contributor.(*Repository)
		}
	}
	if phase == nil || repo == nil || w.state.emailRemoval != nil {
		return w.fail(ctx, invalidEmailRemoval())
	}
	i, d, err := emailRemovalCommand(phase, c, plan.snapshot())
	if err != nil || d.directory.repository != repo {
		return w.fail(ctx, invalidEmailRemoval())
	}
	if i.Administration != (EmailRemovalAdministration{}) {
		if err := lockEmailRemovalSubjects(ctx, w, w.state.binding, i.Administration); err != nil {
			return err
		}
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	remaining := false
	for _, a := range before.Identifiers {
		if a.ID == i.Change.ID {
			if a.Kind != identity.IdentifierEmail || a.Primary && !i.LeavePrimaryUnassigned && i.ReplacementPrimary == (identity.IdentifierPrimarySelection{}) {
				return w.fail(ctx, identity.ForbiddenError{})
			}
		} else if a.Kind == identity.IdentifierEmail && a.Verified {
			remaining = true
		}
	}
	if !remaining {
		return w.fail(ctx, identity.FinalAccessError{})
	}
	mutation, err := identity.ApplyIdentifierChange(before, i.Change, now)
	if i.ReplacementPrimary != (identity.IdentifierPrimarySelection{}) {
		mutation, err = identity.ApplyIdentifierRemovalWithPrimary(before, i.Change, i.ReplacementPrimary, now)
	}
	if err != nil {
		return w.fail(ctx, err)
	}
	w.state.emailRemoval = &emailRemovalProgress{intent: i, domain: d, before: before, mutation: mutation, at: now}
	return nil
}

func applyEmailRemoval(ctx context.Context, w Work) error {
	p := w.state.emailRemoval
	if p == nil || p.applied {
		return w.fail(ctx, invalidEmailRemoval())
	}
	if err := persistIdentifierMutation(ctx, w, w.state.binding, p.intent.Change, p.before, p.mutation, p.domain.directory.reuse, p.at); err != nil {
		return err
	}
	p.applied = true
	return nil
}

func recoverEmailRemoval(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || w.state.plan.lifecycle == nil {
		return RecoveryUnknown, invalidEmailRemoval()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers i WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3 AND i.kind='email' AND i.version=$4 AND NOT EXISTS(SELECT 1 FROM identity.identifier_retirements r WHERE r.tenant_id=i.tenant_id AND r.identifier_id=i.identifier_id))`, string(b.TenantID), string(b.UserID), b.RecordID, w.state.plan.lifecycle.BeforeVersion)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var unchanged bool
	if !rows.Next() || rows.Scan(&unchanged) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if unchanged {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}

// Format omits original account/address correlation and intent.
func (EmailRemovalIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailRemovalIntent(redacted)"))
}

// MarshalJSON denies implicit sensitive intent export.
func (EmailRemovalIntent) MarshalJSON() ([]byte, error) { return nil, invalidEmailRemoval() }

// Format hides native directory and immutable key/policy custody.
func (EmailRemovalDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailRemovalDomain(redacted)"))
}

// MarshalJSON denies implicit native custody export.
func (EmailRemovalDomain) MarshalJSON() ([]byte, error) { return nil, invalidEmailRemoval() }

// Format hides retained directory keys and policy configuration.
func (EmailRemovalDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailRemovalDomainConfig(redacted)"))
}

// MarshalJSON denies implicit native key/configuration export.
func (EmailRemovalDomainConfig) MarshalJSON() ([]byte, error) { return nil, invalidEmailRemoval() }

func matchesEmailRemovalCascade(actual, expected *identity.LifecycleCascadeAdmission) bool {
	if actual == nil || expected == nil {
		return false
	}
	return actual.CascadeID == expected.CascadeID && actual.Generation == expected.Generation && actual.Kind == expected.Kind && actual.TenantID == expected.TenantID && actual.UserID == expected.UserID && actual.IdentifierID == expected.IdentifierID && actual.AuthorityVersion == expected.AuthorityVersion && actual.ManifestVersion == expected.ManifestVersion && actual.Status == expected.Status && slices.Equal(actual.Owners, expected.Owners) && slices.Equal(actual.ExternalLimitations, expected.ExternalLimitations)
}
