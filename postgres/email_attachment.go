package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// EmailAttachmentIntent names a pending email and exact directory predecessors.
// Values must have been normalized by the selected versioned email owner. It is
// immutable command intent, not proof of possession, authentication or policy.
type EmailAttachmentIntent struct {
	Change            identity.IdentifierChange
	ComparisonProfile string
	// ExistingCanonicalAddress is required only for pending resend. It cannot
	// replace or normalize the stored identity; attachment must leave it empty.
	ExistingCanonicalAddress string
	// Previous is mandatory for change-request and absent for verification.
	Previous ManagedEmailPrevious
}

// EmailAttachmentDomainConfig selects the versioned comparison profile and the
// retained identifier-reuse keys shared with removal/registration. Construction
// copies keys; a missing key referenced by live retirement history denies use.
type EmailAttachmentDomainConfig struct {
	ComparisonProfile           string
	CurrentIdentifierKeyVersion uint32
	RetainedIdentifierKeys      map[uint32][32]byte
}

// EmailAttachmentDomain borrows the exact enlisted kernel repository. Only the
// coordinator uses its immutable storage policy; it owns no transaction, retry,
// resource or goroutine. It is not an independently executable email service.
type EmailAttachmentDomain struct {
	repository *Repository
	comparison string
	reuse      identifierMutationPolicy
}

// EmailAttachmentContributor maps the original native command without IO or
// callbacks. ApplyFeature owns original fresh proof, current session, factor and
// risk admission/consumption; the kernel alone writes the pending email. Final
// checks conserve original validity and may not readmit a newer arbitrary
// directory epoch. Delivery and capability issuance remain separate enlisted
// owners. Implementations must not mutate or retain returned domain/intent.
type EmailAttachmentContributor interface {
	FeatureCommitContributor
	EmailAttachment(identity.Command) (EmailAttachmentIntent, *EmailAttachmentDomain, error)
}

func invalidEmailAttachment() error { return identity.InvalidInputError{Field: "email_attachment"} }

// NewEmailAttachmentDomain validates and copies explicit native composition
// without IO. Install IdentifierMutationMigrationSource before execution. This
// constructor does not authorize attachment or make a verification link valid.
func NewEmailAttachmentDomain(r *Repository, c EmailAttachmentDomainConfig) (*EmailAttachmentDomain, error) {
	if r == nil || r.pool == nil || r.read == nil || len(c.RetainedIdentifierKeys) > 16 {
		return nil, invalidEmailAttachment()
	}
	if _, err := identity.ParseIdentifierID(c.ComparisonProfile); err != nil {
		return nil, invalidEmailAttachment()
	}
	p := identifierMutationPolicy{currentKeyVersion: c.CurrentIdentifierKeyVersion, keys: make(map[uint32][32]byte, len(c.RetainedIdentifierKeys))}
	for version, key := range c.RetainedIdentifierKeys {
		p.keys[version] = key
	}
	if !p.valid() {
		return nil, invalidEmailAttachment()
	}
	return &EmailAttachmentDomain{repository: r, comparison: strings.Clone(c.ComparisonProfile), reuse: p}, nil
}

// EmailAttachmentFields returns every kernel-owned canonical input. Include
// these unchanged before fingerprinting. Structural bounds do not normalize
// addresses or confer current authority. Pending email attachment and its distinct
// native resend profile are supported; verify, replace, primary selection and
// removal are separate flows. Resend retains exact target predecessors and the
// unchanged canonical mailbox.
func EmailAttachmentFields(s EmailAttachmentIntent) ([]identity.FeatureField, error) {
	c := s.Change
	resend := c.Action == identity.IdentifierRestartVerification
	canonical := c.CanonicalValue
	if resend {
		canonical = s.ExistingCanonicalAddress
	}
	if _, err := identity.IdentifierIntentDigest(c); err != nil || (c.Action != identity.IdentifierAttach && !resend) || !resend && (c.Kind != identity.IdentifierEmail || s.ExistingCanonicalAddress != "") || canonical == "" || len(canonical) > 254 || len(c.DisplayValue) > 254 || c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == ^uint64(0) {
		return nil, invalidEmailAttachment()
	}
	if _, err := identity.ParseIdentifierID(s.ComparisonProfile); err != nil {
		return nil, invalidEmailAttachment()
	}
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "email-attachment." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "email-attachment." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	fields := []identity.FeatureField{text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)), text("canonical-address", canonical), text("display-address", c.DisplayValue), text("comparison-profile", s.ComparisonProfile), number("user-version", c.ExpectedUserVersion), number("authority-version", c.ExpectedAuthorityVersion)}
	if resend {
		fields = append(fields, number("identifier-version", c.ExpectedIdentifierVersion), number("verification-version", c.ExpectedVerificationVersion))
	}
	previous, err := previousEmailFields(s.Previous, c.ID, "email-attachment.")
	if err != nil || resend && len(previous) != 0 {
		return nil, invalidEmailAttachment()
	}
	return append(fields, previous...), nil
}

func emailResendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-send", SchemaID: "identity.email.verification-send.resend-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func emailAttachmentOperation(op identity.FeatureOperation) bool {
	if op == emailResendOperation() {
		return true
	}
	for _, action := range []string{"identity.email.verification-send", "identity.email.change-request"} {
		if op == (identity.FeatureOperation{Owner: "identity/email", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) {
			return true
		}
	}
	return false
}

func managedEmailRequestLifecycle(op identity.FeatureOperation, life *LifecyclePlan) bool {
	if life == nil {
		return false
	}
	if op == emailResendOperation() {
		return life.EventType == "identifier.verification-requested.v1" && life.BeforeVersion > 0 && life.BeforeVersion < ^uint64(0) && life.AfterVersion == life.BeforeVersion+1
	}
	return life.EventType == "identifier.attached.v1" && life.BeforeVersion == 0 && life.AfterVersion == 1
}

// Original-user issuance is a closed management profile, not a general grant
// transformation. The existing native plan codec, registered attachment owner
// and staged issuer/delivery custody independently enforce execution.
func validManagedEmailIssuance(b identity.CommandBinding, p CommandPlan) bool {
	i := p.CapabilityIssuance
	if i == nil || p.Feature == nil || !emailAttachmentOperation(p.Feature.Operation) || b.ValidateFor(p.Feature.Operation) != nil || b.UserID == "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || p.SubjectType != "identifier" || !managedEmailRequestLifecycle(p.Feature.Operation, p.Lifecycle) || i.RegistrationUserID != "" || i.ResetRecipientUserID != "" || i.MagicLinkRecipientUserID != "" || i.MFAContinuationUserID != "" || len(i.Grants) != 1 || i.Grants[0].Purpose != "identity.identifier.verify" || p.Delivery == nil || !validDeliveryPlan(p.Delivery) || len(p.Delivery.Intents) != 1 {
		return false
	}
	d := p.Delivery.Intents[0]
	return d.SubjectID == string(b.UserID) && d.Purpose == "identity.email.verification-request" && d.ExpiresAt.Equal(i.Grants[0].ExpiresAt)
}

func emailAttachmentCommand(p EmailAttachmentContributor, command identity.Command, plan CommandPlan) (EmailAttachmentIntent, *EmailAttachmentDomain, error) {
	s, ok := commandFeature(command)
	if !ok || plan.Feature == nil || !emailAttachmentOperation(s.Operation) || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || plan.SubjectType != "identifier" || plan.Capability != nil || plan.OTP != nil || !managedEmailRequestLifecycle(s.Operation, plan.Lifecycle) || s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	if _, present := command.SessionToken(); !present {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	for _, a := range plan.Audits {
		if a.RetentionClass != "protected" {
			return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
		}
	}
	intent, domain, err := p.EmailAttachment(command)
	if err != nil || domain == nil || domain.repository == nil || !domain.reuse.valid() || domain.comparison != intent.ComparisonProfile {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	if (s.Operation.OperationID == "identity.email.change-request") != (intent.Previous != (ManagedEmailPrevious{})) {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	if s.Operation == emailResendOperation() {
		if intent.Change.Action != identity.IdentifierRestartVerification || intent.Change.ExpectedVerificationVersion != plan.Lifecycle.BeforeVersion {
			return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
		}
	} else if intent.Change.Action != identity.IdentifierAttach {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	fields, err := EmailAttachmentFields(intent)
	if err != nil || intent.Change.TenantID != s.Binding.TenantID || intent.Change.UserID != s.Binding.UserID || string(intent.Change.ID) != s.Binding.RecordID {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	matched := 0
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "email-attachment.") {
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
				return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
			}
			found = true
			matched++
			break
		}
		if !found {
			return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
		}
	}
	if matched != len(fields) {
		return EmailAttachmentIntent{}, nil, invalidEmailAttachment()
	}
	return intent, domain, nil
}

type emailAttachmentProgress struct {
	intent   EmailAttachmentIntent
	domain   *EmailAttachmentDomain
	before   identity.IdentifierState
	mutation identity.IdentifierMutation
	at       time.Time
	applied  bool
}

func prepareEmailAttachment(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var phase EmailAttachmentContributor
	var repo *Repository
	for _, entry := range plan.contributors {
		if entry.descriptor == plan.feature.Contributor {
			phase, _ = entry.contributor.(EmailAttachmentContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repo, _ = entry.contributor.(*Repository)
		}
	}
	if phase == nil || repo == nil || w.state.emailAttachment != nil {
		return w.fail(ctx, invalidEmailAttachment())
	}
	intent, domain, err := emailAttachmentCommand(phase, command, plan.snapshot())
	if err != nil || domain == nil || domain.repository != repo {
		return w.fail(ctx, invalidEmailAttachment())
	}
	before, now, err := lockIdentifierPartition(ctx, w, intent.Change)
	if err != nil {
		return err
	}
	if intent.Previous != (ManagedEmailPrevious{}) {
		if err := checkPreviousEmail(before, intent.Previous, intent.Change.ID); err != nil {
			return w.fail(ctx, err)
		}
	}
	if intent.Change.Action == identity.IdentifierRestartVerification {
		matched := false
		for _, record := range before.Identifiers {
			if record.ID == intent.Change.ID {
				matched = record.Kind == identity.IdentifierEmail && record.CanonicalValue == intent.ExistingCanonicalAddress
			}
		}
		if !matched {
			return w.fail(ctx, identity.ForbiddenError{})
		}
	}
	mutation, err := identity.ApplyIdentifierChange(before, intent.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	if err := checkIdentifierReuse(ctx, w, intent.Change, domain.reuse, now); err != nil {
		return err
	}
	w.state.emailAttachment = &emailAttachmentProgress{intent: intent, domain: domain, before: before, mutation: mutation, at: now}
	return nil
}

func applyEmailAttachment(ctx context.Context, w Work) error {
	p := w.state.emailAttachment
	if p == nil || p.applied {
		return w.fail(ctx, invalidEmailAttachment())
	}
	if err := persistIdentifierMutation(ctx, w, w.state.binding, p.intent.Change, p.before, p.mutation, p.domain.reuse, p.at); err != nil {
		return err
	}
	p.applied = true
	return nil
}

// Format redacts address, account and key material from implicit diagnostics.
func (EmailAttachmentIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailAttachmentIntent(redacted)"))
}

// MarshalJSON refuses implicit export of correlated address intent.
func (EmailAttachmentIntent) MarshalJSON() ([]byte, error) { return nil, invalidEmailAttachment() }

// Format redacts the immutable native key configuration.
func (EmailAttachmentDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailAttachmentDomainConfig(redacted)"))
}

// MarshalJSON refuses implicit export of native keys.
func (EmailAttachmentDomainConfig) MarshalJSON() ([]byte, error) {
	return nil, invalidEmailAttachment()
}

// Format redacts borrowed directory and key custody.
func (EmailAttachmentDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailAttachmentDomain(redacted)"))
}

// MarshalJSON refuses implicit export of borrowed native custody.
func (EmailAttachmentDomain) MarshalJSON() ([]byte, error) { return nil, invalidEmailAttachment() }
