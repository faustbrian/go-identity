package postgres

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// UsernameRenameIntent freezes a comparison-bound username and every directory
// predecessor. It neither normalizes values nor proves current authority.
type UsernameRenameIntent struct{ Change identity.IdentifierChange }

// UsernameRenameDomainConfig selects the unchanged stored comparison profile
// and identifier-reuse policy. Retained keys are copied. ReuseCooldown is an
// explicit microsecond-exact duration within 0..365 days; live retirement expiry
// is never recomputed when configuration changes. Missing historical keys deny.
type UsernameRenameDomainConfig struct {
	NormalizationProfile        string
	NormalizationVersion        uint32
	CurrentIdentifierKeyVersion uint32
	RetainedIdentifierKeys      map[uint32][32]byte
	ReuseCooldown               time.Duration
}

// UsernameRenameDomain borrows the exact enlisted directory writer and freezes
// policy. It owns no transaction, pool, retry, callback, journal or goroutine.
type UsernameRenameDomain struct {
	repository *Repository
	profile    string
	version    uint32
	reuse      identifierMutationPolicy
}

// UsernameRenameContributor supplies immutable original intent. Its native
// execution owns original password proof, session, current factors, policy and
// risk; only the kernel writes identifiers and keyed retirement history. Final
// checks must retain original epochs/expiry, not admit a new arbitrary snapshot.
type UsernameRenameContributor interface {
	FeatureCommitContributor
	UsernameRename(identity.Command) (UsernameRenameIntent, *UsernameRenameDomain, error)
}

func invalidUsernameRename() error { return identity.InvalidInputError{Field: "username_rename"} }

// NewUsernameRenameDomain copies policy without IO. Install the identifier
// normalization and retirement histories before execution; this constructor
// neither authorizes renaming nor migrates unbound historical usernames.
func NewUsernameRenameDomain(r *Repository, c UsernameRenameDomainConfig) (*UsernameRenameDomain, error) {
	if r == nil || r.pool == nil || r.read == nil || c.NormalizationVersion == 0 || len(c.RetainedIdentifierKeys) > 16 {
		return nil, invalidUsernameRename()
	}
	if _, err := identity.ParseIdentifierID(c.NormalizationProfile); err != nil {
		return nil, invalidUsernameRename()
	}
	p := identifierMutationPolicy{currentKeyVersion: c.CurrentIdentifierKeyVersion, keys: maps.Clone(c.RetainedIdentifierKeys), reuseCooldown: c.ReuseCooldown}
	if !p.valid() {
		return nil, invalidUsernameRename()
	}
	return &UsernameRenameDomain{repository: r, profile: strings.Clone(c.NormalizationProfile), version: c.NormalizationVersion, reuse: p}, nil
}

// UsernameRenameFields returns complete kernel-owned typed intent. Preserve
// these unchanged when fingerprinting. The workflow owner must validate names
// through its selected policy; structural acceptance grants no reservation or
// authentication. Display-only edits still bind every original predecessor.
func UsernameRenameFields(i UsernameRenameIntent) ([]identity.FeatureField, error) {
	c := i.Change
	if _, err := identity.IdentifierIntentDigest(c); err != nil || c.Action != identity.IdentifierRename || c.Kind != identity.IdentifierUsername || c.NormalizationProfile == "" || c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == ^uint64(0) || c.ExpectedIdentifierVersion == ^uint64(0) || c.ExpectedVerificationVersion == ^uint64(0) {
		return nil, invalidUsernameRename()
	}
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "username-rename." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "username-rename." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	return []identity.FeatureField{
		text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)),
		text("canonical", c.CanonicalValue), text("display", c.DisplayValue), text("normalization-profile", c.NormalizationProfile),
		number("normalization-version", uint64(c.NormalizationVersion)), number("user-version", c.ExpectedUserVersion),
		number("authority-version", c.ExpectedAuthorityVersion), number("identifier-version", c.ExpectedIdentifierVersion), number("verification-version", c.ExpectedVerificationVersion),
	}, nil
}

func usernameRenameOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/username", OperationID: "identity.username.update", SchemaID: "identity.username.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func usernameRenameCommand(p UsernameRenameContributor, command identity.Command, plan CommandPlan) (UsernameRenameIntent, *UsernameRenameDomain, error) {
	s, ok := commandFeature(command)
	if !ok || s.Operation != usernameRenameOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}) || plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.updated.v1" || plan.Lifecycle.BeforeVersion == 0 || plan.Lifecycle.BeforeVersion == ^uint64(0) || plan.Lifecycle.AfterVersion != plan.Lifecycle.BeforeVersion+1 || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.OTP != nil || plan.Delivery != nil || s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) {
		return UsernameRenameIntent{}, nil, invalidUsernameRename()
	}
	if _, present := command.SessionToken(); !present {
		return UsernameRenameIntent{}, nil, invalidUsernameRename()
	}
	for _, a := range plan.Audits {
		if !a.Required || a.RetentionClass != "protected" {
			return UsernameRenameIntent{}, nil, invalidUsernameRename()
		}
	}
	i, d, err := p.UsernameRename(command)
	if err != nil || d == nil || d.repository == nil || !d.reuse.valid() || d.profile != i.Change.NormalizationProfile || d.version != i.Change.NormalizationVersion || i.Change.ExpectedIdentifierVersion != plan.Lifecycle.BeforeVersion || i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID || string(i.Change.ID) != s.Binding.RecordID {
		return UsernameRenameIntent{}, nil, invalidUsernameRename()
	}
	fields, err := UsernameRenameFields(i)
	if err != nil {
		return UsernameRenameIntent{}, nil, err
	}
	matched := 0
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "username-rename.") {
			continue
		}
		found := false
		for _, expected := range fields {
			if actual.Name != expected.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if actual.Value.Kind != expected.Value.Kind || ea != nil || eb != nil || !bytes.Equal(a, b) {
				return UsernameRenameIntent{}, nil, invalidUsernameRename()
			}
			found, matched = true, matched+1
			break
		}
		if !found {
			return UsernameRenameIntent{}, nil, invalidUsernameRename()
		}
	}
	if matched != len(fields) {
		return UsernameRenameIntent{}, nil, invalidUsernameRename()
	}
	return i, d, nil
}

type usernameRenameProgress struct {
	intent   UsernameRenameIntent
	domain   *UsernameRenameDomain
	before   identity.IdentifierState
	mutation identity.IdentifierMutation
	at       time.Time
	applied  bool
}

func prepareUsernameRename(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var phase UsernameRenameContributor
	var repository *Repository
	for _, e := range plan.contributors {
		if e.descriptor == plan.feature.Contributor {
			phase, _ = e.contributor.(UsernameRenameContributor)
		}
		if e.descriptor.Owner == "identity/postgres" {
			repository, _ = e.contributor.(*Repository)
		}
	}
	if phase == nil || repository == nil || w.state.usernameRename != nil {
		return w.fail(ctx, invalidUsernameRename())
	}
	i, d, err := usernameRenameCommand(phase, command, plan.snapshot())
	if err != nil || d == nil || d.repository != repository {
		return w.fail(ctx, invalidUsernameRename())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	mutation, err := identity.ApplyIdentifierChange(before, i.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	// Display-only edits retain the existing reservation and verified state.
	// Only a new canonical value competes with signup/retired-name reuse.
	if mutation.Retired != nil {
		if err := checkIdentifierReuse(ctx, w, i.Change, d.reuse, now); err != nil {
			return err
		}
	}
	w.state.usernameRename = &usernameRenameProgress{intent: i, domain: d, before: before, mutation: mutation, at: now}
	return nil
}

func applyUsernameRename(ctx context.Context, w Work) error {
	p := w.state.usernameRename
	if p == nil || p.applied {
		return w.fail(ctx, invalidUsernameRename())
	}
	if err := persistIdentifierMutation(ctx, w, w.state.binding, p.intent.Change, p.before, p.mutation, p.domain.reuse, p.at); err != nil {
		return err
	}
	p.applied = true
	return nil
}

func recoverUsernameRename(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || w.state.plan.lifecycle == nil || w.state.plan.lifecycle.BeforeVersion == 0 {
		return RecoveryUnknown, invalidUsernameRename()
	}
	// Only the unchanged locked predecessor is negative evidence. A successor
	// or missing record never synthesizes a receipt; all participants and the
	// existing original command journal must independently reconcile durability.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND kind='username' AND version=$4)`, string(b.TenantID), string(b.UserID), b.RecordID, w.state.plan.lifecycle.BeforeVersion)
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

// Format redacts correlated original identity/name intent.
func (UsernameRenameIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.UsernameRenameIntent(redacted)"))
}

// MarshalJSON denies implicit export of correlated original intent.
func (UsernameRenameIntent) MarshalJSON() ([]byte, error) { return nil, invalidUsernameRename() }

// Format redacts borrowed native custody and retained keys.
func (UsernameRenameDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.UsernameRenameDomain(redacted)"))
}

// MarshalJSON denies implicit export of borrowed native custody.
func (UsernameRenameDomain) MarshalJSON() ([]byte, error) { return nil, invalidUsernameRename() }

// Format redacts retained key material and configuration.
func (UsernameRenameDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.UsernameRenameDomainConfig(redacted)"))
}

// MarshalJSON denies implicit export of retained keys.
func (UsernameRenameDomainConfig) MarshalJSON() ([]byte, error) { return nil, invalidUsernameRename() }
