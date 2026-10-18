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

// PhoneEnrollmentIntent is the kernel's original pending-phone input. The
// phone owner must first validate the number under its exact metadata-bound
// policy. These fields are sensitive intent, never ownership or authorization.
type PhoneEnrollmentIntent struct{ Change identity.IdentifierChange }

// PhoneEnrollmentDomainConfig binds the phone owner's stored normalization
// identity and explicit recycling policy. Retained reuse keys are copied. The
// positive microsecond-exact cooldown is at most 365 days; an existing retirement
// keeps its original expiry. A new metadata profile never rewrites old records.
type PhoneEnrollmentDomainConfig struct {
	NormalizationProfile        string
	NormalizationVersion        uint32
	CurrentIdentifierKeyVersion uint32
	RetainedIdentifierKeys      map[uint32][32]byte
	ReuseCooldown               time.Duration
}

// PhoneEnrollmentDomain retains the exact borrowed kernel writer and immutable
// identifier policy. It owns no pool, transaction, retry, callback or goroutine.
// Construction alone does not expose an enrollment operation or storage writer.
type PhoneEnrollmentDomain struct {
	repository *Repository
	profile    string
	version    uint32
	reuse      identifierMutationPolicy
}

// PhoneEnrollmentContributor supplies original phone intent to the coordinator.
// ApplyFeature must admit and consume the original action-bound proof, current
// session, factors and risk, and persist its OTP and delivery atomically in Work.
// Only the kernel writes the pending identifier. Final CheckFeatureCommit keeps
// the original validity bounds; it must not readmit a newer directory epoch.
type PhoneEnrollmentContributor interface {
	FeatureCommitContributor
	PhoneEnrollment(identity.Command) (PhoneEnrollmentIntent, *PhoneEnrollmentDomain, error)
}

func invalidPhoneEnrollment() error {
	return identity.InvalidInputError{Field: "phone_enrollment"}
}

// NewPhoneEnrollmentDomain freezes explicit native policy without IO. Install
// the existing identifier normalization/retirement histories before execution.
// The native phone workflow must match this profile to its real NumberPolicy;
// this constructor neither supplies metadata validation nor reserves a number.
func NewPhoneEnrollmentDomain(r *Repository, c PhoneEnrollmentDomainConfig) (*PhoneEnrollmentDomain, error) {
	if r == nil || r.pool == nil || r.read == nil || c.NormalizationVersion == 0 ||
		len(c.NormalizationProfile) == 0 || len(c.NormalizationProfile) > 128 ||
		len(c.RetainedIdentifierKeys) > 16 || c.ReuseCooldown <= 0 {
		return nil, invalidPhoneEnrollment()
	}
	// Keep the root identifier's persisted profile-ID grammar. Number parsing
	// belongs to phone; a storage profile cannot contain ambiguous separators.
	for i := range c.NormalizationProfile {
		b := c.NormalizationProfile[i]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || i > 0 && (b == '.' || b == '_' || b == '-') {
			continue
		}
		return nil, invalidPhoneEnrollment()
	}
	p := identifierMutationPolicy{currentKeyVersion: c.CurrentIdentifierKeyVersion,
		keys: maps.Clone(c.RetainedIdentifierKeys), reuseCooldown: c.ReuseCooldown}
	if !p.valid() {
		return nil, invalidPhoneEnrollment()
	}
	return &PhoneEnrollmentDomain{repository: r, profile: strings.Clone(c.NormalizationProfile), version: c.NormalizationVersion, reuse: p}, nil
}

// PhoneEnrollmentFields freezes complete pending-attachment input before the
// coordinator fingerprints it. It accepts only a new phone identifier, not
// email, verification, replacement, primary selection or a caller's verified
// status. E.164 shape is checked defensively; actual pinned-metadata validity
// remains the phone owner's responsibility. No IO or normalization occurs.
func PhoneEnrollmentFields(i PhoneEnrollmentIntent) ([]identity.FeatureField, error) {
	c := i.Change
	if _, err := identity.IdentifierIntentDigest(c); err != nil ||
		c.Action != identity.IdentifierAttach || c.Kind != identity.IdentifierPhone ||
		c.NormalizationProfile == "" || c.NormalizationVersion == 0 ||
		len(c.DisplayValue) > 128 || c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == ^uint64(0) ||
		!phoneEnrollmentNumberShape(c.CanonicalValue) {
		return nil, invalidPhoneEnrollment()
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "phone-enrollment." + name,
			Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "phone-enrollment." + name,
			Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{
		text("tenant", string(c.TenantID)), text("user", string(c.UserID)),
		text("identifier", string(c.ID)), text("canonical-number", c.CanonicalValue),
		text("display-number", c.DisplayValue), text("normalization-profile", c.NormalizationProfile),
		number("normalization-version", uint64(c.NormalizationVersion)),
		number("user-version", c.ExpectedUserVersion), number("authority-version", c.ExpectedAuthorityVersion),
	}, nil
}

func phoneEnrollmentNumberShape(s string) bool {
	if len(s) < 3 || len(s) > 16 || s[0] != '+' || s[1] < '1' || s[1] > '9' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func phoneEnrollmentOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.send-verification",
		SchemaID: "identity.phone.send-verification.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func phoneEnrollmentCommand(p PhoneEnrollmentContributor, command identity.Command, plan CommandPlan) (PhoneEnrollmentIntent, *PhoneEnrollmentDomain, error) {
	s, ok := commandFeature(command)
	if !ok || p == nil || s.Operation != phoneEnrollmentOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation ||
		plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) ||
		plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.attached.v1" ||
		plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 || plan.Capability != nil || plan.CapabilityIssuance != nil ||
		plan.OTP != nil || s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) || len(plan.Audits) == 0 {
		return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
	}
	if _, present := command.SessionToken(); !present {
		return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
	}
	for _, audit := range plan.Audits {
		if !audit.Required || audit.RetentionClass != "protected" {
			return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
		}
	}
	i, d, err := p.PhoneEnrollment(command)
	if err != nil || d == nil || d.repository == nil || !d.reuse.valid() || d.reuse.reuseCooldown <= 0 ||
		d.profile != i.Change.NormalizationProfile || d.version != i.Change.NormalizationVersion ||
		i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID || string(i.Change.ID) != s.Binding.RecordID {
		return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
	}
	fields, err := PhoneEnrollmentFields(i)
	if err != nil {
		return PhoneEnrollmentIntent{}, nil, err
	}
	seen := make(map[string]bool, len(fields))
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "phone-enrollment.") {
			continue
		}
		if seen[actual.Name] {
			return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
		}
		found := false
		for _, expected := range fields {
			if actual.Name != expected.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if actual.Value.Kind != expected.Value.Kind || ea != nil || eb != nil || !bytes.Equal(a, b) {
				return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
			}
			found = true
			seen[actual.Name] = true
			break
		}
		if !found {
			return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
		}
	}
	if len(seen) != len(fields) {
		return PhoneEnrollmentIntent{}, nil, invalidPhoneEnrollment()
	}
	return i, d, nil
}

type phoneEnrollmentProgress struct {
	intent   PhoneEnrollmentIntent
	domain   *PhoneEnrollmentDomain
	before   identity.IdentifierState
	mutation identity.IdentifierMutation
	at       time.Time
	applied  bool
}

// RequirePhoneEnrollmentCandidate permits only the exact prepared candidate in
// this registered owner's synchronous Apply invocation, before kernel apply.
// It is the candidate counterpart of RequireRecipient: it does not fabricate
// an existing/verified recipient. Proof, current session, factor and risk checks
// remain the native owner's responsibility. No IO or callbacks run; mismatch
// poisons Work so ignored denial cannot commit a staged OTP or SMS delivery.
func (w Work) RequirePhoneEnrollmentCandidate(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected PhoneEnrollmentIntent) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	p := w.state.phoneEnrollment
	if w.state.feature.Operation != phoneEnrollmentOperation() ||
		w.state.feature.Contributor != (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) ||
		p == nil || p.applied || p.intent != expected {
		return w.fail(ctx, invalidPhoneEnrollment())
	}
	if _, ok := owner.(PhoneEnrollmentContributor); !ok {
		return w.fail(ctx, invalidPhoneEnrollment())
	}
	return nil
}

func preparePhoneEnrollment(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var phase PhoneEnrollmentContributor
	var repository *Repository
	for _, entry := range plan.contributors {
		if entry.descriptor == plan.feature.Contributor {
			phase, _ = entry.contributor.(PhoneEnrollmentContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repository, _ = entry.contributor.(*Repository)
		}
	}
	if phase == nil || repository == nil || w.state.phoneEnrollment != nil {
		return w.fail(ctx, invalidPhoneEnrollment())
	}
	i, d, err := phoneEnrollmentCommand(phase, command, plan.snapshot())
	if err != nil || d == nil || d.repository != repository {
		return w.fail(ctx, invalidPhoneEnrollment())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	mutation, err := identity.ApplyIdentifierChange(before, i.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	if err := checkIdentifierReuse(ctx, w, i.Change, d.reuse, now); err != nil {
		return err
	}
	w.state.phoneEnrollment = &phoneEnrollmentProgress{intent: i, domain: d, before: before, mutation: mutation, at: now}
	return nil
}

func applyPhoneEnrollment(ctx context.Context, w Work) error {
	p := w.state.phoneEnrollment
	if p == nil || p.applied {
		return w.fail(ctx, invalidPhoneEnrollment())
	}
	// Native proof consumption and OTP/delivery writes happen first, while the
	// locked directory still has its original epochs. Persist only afterward,
	// exactly as pending email attachment does, in the same coordinator Work.
	if err := persistIdentifierMutation(ctx, w, w.state.binding, p.intent.Change, p.before, p.mutation, p.domain.reuse, p.at); err != nil {
		return err
	}
	p.applied = true
	return nil
}

// Format prevents ordinary diagnostics from disclosing number intent.
func (PhoneEnrollmentIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneEnrollmentIntent(redacted)"))
}

// MarshalJSON requires an explicit protected persistence projection.
func (PhoneEnrollmentIntent) MarshalJSON() ([]byte, error) { return nil, invalidPhoneEnrollment() }

// Format hides retained reuse keys and correlated storage configuration.
func (PhoneEnrollmentDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneEnrollmentDomainConfig(redacted)"))
}

// MarshalJSON denies implicit key/configuration export.
func (PhoneEnrollmentDomainConfig) MarshalJSON() ([]byte, error) {
	return nil, invalidPhoneEnrollment()
}

// Format hides borrowed writer custody and retained policy.
func (PhoneEnrollmentDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneEnrollmentDomain(redacted)"))
}

// MarshalJSON denies implicit writer/key export.
func (PhoneEnrollmentDomain) MarshalJSON() ([]byte, error) { return nil, invalidPhoneEnrollment() }
