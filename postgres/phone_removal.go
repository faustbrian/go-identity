package postgres

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// PhoneRemovalIntent freezes one verified phone, its stored normalization
// profile and exact directory predecessors. Number and Reason are sensitive
// original intent, not phone possession, recent proof or recovery eligibility.
type PhoneRemovalIntent struct {
	Change               identity.IdentifierChange
	CanonicalNumber      string
	NormalizationProfile string
	NormalizationVersion uint32
	Reason               string
}

// PhoneRemovalDomainConfig selects the existing phone directory/recycling and
// identifier-removal cascade policies. It creates no second writer or journal.
// Retained reuse keys and complete consumer contracts are copied at construction.
type PhoneRemovalDomainConfig struct {
	Directory PhoneEnrollmentDomainConfig
	Cascade   IdentifierRemovalCascadeConfig
}

// PhoneRemovalDomain borrows the exact enlisted directory and frozen policies.
// It owns no pool, transaction, worker, callback or lifecycle acknowledgement.
type PhoneRemovalDomain struct {
	directory *PhoneEnrollmentDomain
	cascade   *identifierRemovalCascadePolicy
}

// PhoneRemovalContributor maps original self-removal intent. The native phase
// owns recent proof, current factors/risk, actual independent recovery eligibility
// and required notices. Only the kernel writes the exact phone/tombstone and
// admits the pending cascade. No OTP participant may be selected for removal.
type PhoneRemovalContributor interface {
	FeatureCommitContributor
	PhoneRemoval(identity.Command) (PhoneRemovalIntent, *PhoneRemovalDomain, error)
}

func invalidPhoneRemoval() error { return identity.InvalidInputError{Field: "phone_removal"} }

// NewPhoneRemovalDomain copies explicit native policy without IO. Install the
// phone directory and forward phone-removal cascade histories before execution.
// Construction grants neither a supported workflow nor arbitrary directory IO.
func NewPhoneRemovalDomain(r *Repository, c PhoneRemovalDomainConfig) (*PhoneRemovalDomain, error) {
	directory, err := NewPhoneEnrollmentDomain(r, c.Directory)
	if err != nil {
		return nil, err
	}
	cascade, err := freezeIdentifierRemovalCascade(c.Cascade)
	if err != nil {
		return nil, err
	}
	return &PhoneRemovalDomain{directory: directory, cascade: cascade}, nil
}

func phoneRemovalOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.remove", SchemaID: "identity.phone.remove.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// PhoneRemovalFields returns all kernel-owned original target/reason fields for
// immutable command fingerprinting. It normalizes nothing, authenticates nothing
// and performs no IO. The native phone owner must validate pinned metadata first.
func PhoneRemovalFields(i PhoneRemovalIntent) ([]identity.FeatureField, error) {
	c := i.Change
	if _, err := identity.IdentifierIntentDigest(c); err != nil || c.Action != identity.IdentifierRemove ||
		c.ExpectedUserVersion == 0 || c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == 0 || c.ExpectedAuthorityVersion == ^uint64(0) ||
		!phoneEnrollmentNumberShape(i.CanonicalNumber) || i.NormalizationVersion == 0 || len(i.Reason) > 64 || !featureEventName(i.Reason) {
		return nil, invalidPhoneRemoval()
	}
	if _, err := identity.ParseIdentifierID(i.NormalizationProfile); err != nil {
		return nil, invalidPhoneRemoval()
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "phone-removal." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "phone-removal." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{
		text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)),
		text("canonical-number", i.CanonicalNumber), text("normalization-profile", i.NormalizationProfile), text("reason", i.Reason),
		number("normalization-version", uint64(i.NormalizationVersion)), number("user-version", c.ExpectedUserVersion), number("authority-version", c.ExpectedAuthorityVersion),
		number("identifier-version", c.ExpectedIdentifierVersion), number("verification-version", c.ExpectedVerificationVersion),
	}, nil
}

func phoneRemovalCommand(owner PhoneRemovalContributor, command identity.Command, plan CommandPlan) (PhoneRemovalIntent, *PhoneRemovalDomain, error) {
	s, ok := commandFeature(command)
	if !ok || owner == nil || s.Operation != phoneRemovalOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation ||
		plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) ||
		plan.SubjectType != "identifier" || plan.OTP != nil || plan.Capability != nil || plan.CapabilityIssuance != nil ||
		plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.removed.v1" || len(plan.Audits) == 0 ||
		s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) {
		return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
	}
	if _, present := command.SessionToken(); !present {
		return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
	}
	for _, audit := range plan.Audits {
		if !audit.Required || audit.RetentionClass != "protected" {
			return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
		}
	}
	i, d, err := owner.PhoneRemoval(command)
	if err != nil || d == nil || d.directory == nil || d.directory.repository == nil || !d.directory.reuse.valid() || d.cascade == nil ||
		d.directory.profile != i.NormalizationProfile || d.directory.version != i.NormalizationVersion || !slices.Contains(d.cascade.config.Reasons, i.Reason) ||
		i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID || string(i.Change.ID) != s.Binding.RecordID ||
		plan.Lifecycle.BeforeVersion != i.Change.ExpectedIdentifierVersion || plan.Lifecycle.AfterVersion != i.Change.ExpectedIdentifierVersion+1 {
		return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
	}
	fields, err := PhoneRemovalFields(i)
	if err != nil {
		return PhoneRemovalIntent{}, nil, err
	}
	seen := make(map[string]bool, len(fields))
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "phone-removal.") {
			continue
		}
		if seen[actual.Name] {
			return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
		}
		for _, expected := range fields {
			if actual.Name != expected.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if actual.Value.Kind != expected.Value.Kind || ea != nil || eb != nil || !bytes.Equal(a, b) {
				return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
			}
			seen[actual.Name] = true
			break
		}
		if !seen[actual.Name] {
			return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
		}
	}
	if len(seen) != len(fields) {
		return PhoneRemovalIntent{}, nil, invalidPhoneRemoval()
	}
	return i, d, nil
}

func phoneRemovalTarget(state identity.IdentifierState, i PhoneRemovalIntent) bool {
	if state.User.Version != i.Change.ExpectedUserVersion || state.AuthorityVersion != i.Change.ExpectedAuthorityVersion {
		return false
	}
	for _, identifier := range state.Identifiers {
		if identifier.ID != i.Change.ID || identifier.Kind != identity.IdentifierPhone || !identifier.Verified || identifier.CanonicalValue != i.CanonicalNumber ||
			identifier.Version != i.Change.ExpectedIdentifierVersion || identifier.NormalizationProfile != i.NormalizationProfile || identifier.NormalizationVersion != i.NormalizationVersion {
			continue
		}
		for _, verification := range state.Verifications {
			if verification.IdentifierID == identifier.ID && verification.Version == i.Change.ExpectedVerificationVersion && verification.State == identity.VerificationVerified && !verification.VerifiedAt.IsZero() {
				return true
			}
		}
	}
	return false
}

// RequirePhoneRemovalTarget locks the exact original verified partition in the
// synchronous preparation admission, before credential/session/factor locks.
// It compares all original predecessors and poisons Work on mismatch. No OTP,
// removal, proof use, notice or new authority is created by this target check.
func (w Work) RequirePhoneRemovalTarget(ctx context.Context, owner PhoneRemovalContributor, command identity.Command) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidPhoneRemoval())
	}
	b, registration, _, err := w.FeatureScope(owner)
	p := w.state.featurePreparationPlan
	if err != nil || p == nil || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != command || p.binding != b || registration.Operation != phoneRemovalOperation() {
		return w.fail(ctx, invalidPhoneRemoval())
	}
	i, d, err := phoneRemovalCommand(owner, command, p.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	matched := false
	for _, entry := range p.contributors {
		matched = matched || entry.contributor == d.directory.repository
	}
	if !matched {
		return w.fail(ctx, invalidPhoneRemoval())
	}
	state, _, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	if !phoneRemovalTarget(state, i) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}

func preparePhoneRemoval(ctx context.Context, w Work, command identity.Command) error {
	p := w.state.execution.reservation.plan
	var owner PhoneRemovalContributor
	var repository *Repository
	for _, entry := range p.contributors {
		if entry.descriptor == p.feature.Contributor {
			owner, _ = entry.contributor.(PhoneRemovalContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repository, _ = entry.contributor.(*Repository)
		}
	}
	if owner == nil || repository == nil || w.state.phoneRemoval != nil {
		return w.fail(ctx, invalidPhoneRemoval())
	}
	i, d, err := phoneRemovalCommand(owner, command, p.snapshot())
	if err != nil || d.directory.repository != repository {
		return w.fail(ctx, invalidPhoneRemoval())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	if !phoneRemovalTarget(before, i) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	mutation, err := identity.ApplyIdentifierChange(before, i.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	// After its exact typed phone gate, removal uses the same private CAS,
	// retirement and pending-cascade storage as email removal. These legacy
	// internal carrier names do not select an email workflow or another journal.
	w.state.phoneRemoval = &emailRemovalProgress{intent: EmailRemovalIntent{Change: i.Change, Reason: i.Reason}, domain: &EmailRemovalDomain{directory: &EmailAttachmentDomain{repository: repository, comparison: i.NormalizationProfile, reuse: d.directory.reuse}, cascade: d.cascade}, before: before, mutation: mutation, at: now}
	return nil
}

func applyPhoneRemoval(ctx context.Context, w Work) error {
	return applyIdentifierRemoval(ctx, w, w.state.phoneRemoval)
}

func recoverPhoneRemoval(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoverIdentifierRemoval(ctx, w, "phone")
}

// Format omits original phone, reason and command correlation.
func (PhoneRemovalIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneRemovalIntent(redacted)"))
}

// MarshalJSON denies implicit sensitive intent export.
func (PhoneRemovalIntent) MarshalJSON() ([]byte, error) { return nil, invalidPhoneRemoval() }

// Format hides the borrowed writer and retained policy/key custody.
func (PhoneRemovalDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneRemovalDomain(redacted)"))
}

// MarshalJSON denies implicit native policy export.
func (PhoneRemovalDomain) MarshalJSON() ([]byte, error) { return nil, invalidPhoneRemoval() }

// Format redacts retained directory keys and cascade policy.
func (PhoneRemovalDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneRemovalDomainConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (PhoneRemovalDomainConfig) MarshalJSON() ([]byte, error) { return nil, invalidPhoneRemoval() }
