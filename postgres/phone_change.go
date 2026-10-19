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

// PhoneChangeIntent freezes replacement of an existing verified phone and the
// original SMS issuance. Change is ReplaceVerifiedPhone, not attach or caller-asserted
// verification. The native phone owner must authenticate original new-number
// OTP possession, recent action proof, session and current recovery/risk policy.
// Fields are sensitive original intent and confer no storage authority.
type PhoneChangeIntent struct {
	Change                       identity.IdentifierChange
	PreviousNumber               string
	PreviousNormalizationProfile string
	PreviousNormalizationVersion uint32
	SendCommandID                identity.CommandID
	Reason                       string
}

// PhoneChangeDomainConfig selects the existing phone directory/recycling policy
// and exact pending identifier-change consumers. It creates no second writer,
// journal, OTP engine or acknowledgement authority.
type PhoneChangeDomainConfig struct {
	Directory PhoneEnrollmentDomainConfig
	Cascade   IdentifierChangeCascadeConfig
}

// PhoneChangeDomain borrows the enlisted directory and immutable policies. Its
// closure custody also hides keys from nested diagnostics that bypass Format.
// It owns no pool, transaction, callbacks, timers or goroutines.
type PhoneChangeDomain struct{ read func() *phoneChangeDomain }

type phoneChangeDomain struct {
	directory *PhoneEnrollmentDomain
	cascade   *identifierRemovalCascadePolicy
}

func (d *PhoneChangeDomain) state() *phoneChangeDomain {
	if d == nil || d.read == nil {
		return nil
	}
	return d.read()
}

// PhoneChangeContributor supplies exact original change intent. The native
// owner authenticates recent proof, session/CSRF, current factors/risk and usable
// independent recovery before code comparison and again at final commit. Only
// the kernel writes replacement/retirement and only OTP consumes the SMS code.
type PhoneChangeContributor interface {
	FeatureCommitContributor
	FeatureInputAdmissionContributor
	PhoneChange(identity.Command) (PhoneChangeIntent, *PhoneChangeDomain, error)
}

// NewPhoneChangeDomain copies explicit native policy without IO or side effects.
// Its constructor does not enable replacement, issue SMS or grant possession.
func NewPhoneChangeDomain(r *Repository, c PhoneChangeDomainConfig) (*PhoneChangeDomain, error) {
	directory, err := NewPhoneEnrollmentDomain(r, c.Directory)
	if err != nil {
		return nil, err
	}
	cascade, err := freezeIdentifierChangeCascade(c.Cascade)
	if err != nil {
		return nil, err
	}
	frozen := &phoneChangeDomain{directory: directory, cascade: cascade}
	return &PhoneChangeDomain{read: func() *phoneChangeDomain { return frozen }}, nil
}

func phoneChangeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.update", SchemaID: "identity.phone.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func invalidPhoneChange() error { return identity.InvalidInputError{Field: "phone_change"} }

// PhoneChangeFields freezes both canonical number/profile bindings, exact
// predecessors and original send before coordinator fingerprinting. No IO,
// normalization, OTP comparison or authority admission occurs. The selected
// native compound transition advances every version exactly once, preserving
// the existing feature receipt and lifecycle CAS contract.
func PhoneChangeFields(i PhoneChangeIntent) ([]identity.FeatureField, error) {
	c := i.Change
	if _, err := identity.IdentifierIntentDigest(c); err != nil ||
		c.Action != identity.IdentifierReplaceVerifiedPhone || c.Kind != identity.IdentifierPhone ||
		!phoneEnrollmentNumberShape(c.CanonicalValue) || !phoneEnrollmentNumberShape(i.PreviousNumber) ||
		c.CanonicalValue == i.PreviousNumber || len(c.DisplayValue) > 128 ||
		c.NormalizationProfile == "" || c.NormalizationProfile != i.PreviousNormalizationProfile ||
		c.NormalizationVersion == 0 || c.NormalizationVersion != i.PreviousNormalizationVersion ||
		c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == ^uint64(0) ||
		c.ExpectedIdentifierVersion == ^uint64(0) || c.ExpectedVerificationVersion == ^uint64(0) ||
		len(i.Reason) > 64 || !featureEventName(i.Reason) {
		return nil, invalidPhoneChange()
	}
	if _, err := identity.ParseCommandID(string(i.SendCommandID)); err != nil {
		return nil, invalidPhoneChange()
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "phone-change." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "phone-change." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{
		text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)),
		text("previous-number", i.PreviousNumber), text("new-number", c.CanonicalValue), text("new-display", c.DisplayValue),
		text("previous-normalization-profile", i.PreviousNormalizationProfile), number("previous-normalization-version", uint64(i.PreviousNormalizationVersion)),
		text("normalization-profile", c.NormalizationProfile), number("normalization-version", uint64(c.NormalizationVersion)),
		number("user-version", c.ExpectedUserVersion), number("authority-version", c.ExpectedAuthorityVersion),
		number("identifier-version", c.ExpectedIdentifierVersion), number("verification-version", c.ExpectedVerificationVersion),
		text("send-command", string(i.SendCommandID)), text("reason", i.Reason),
	}, nil
}

func phoneChangeCommand(owner PhoneChangeContributor, command identity.Command, plan CommandPlan) (PhoneChangeIntent, *PhoneChangeDomain, error) {
	s, ok := commandFeature(command)
	if !ok || owner == nil || s.Operation != phoneChangeOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation ||
		plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) ||
		plan.SubjectType != "identifier" || plan.OTP == nil || plan.OTP.Mode != OTPConsume ||
		plan.Capability != nil || plan.CapabilityIssuance != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil ||
		plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.changed.v1" ||
		plan.Delivery == nil || len(plan.Delivery.Intents) != 1 ||
		plan.Delivery.Intents[0].Purpose != "identity.phone.change-notification" || plan.Delivery.Intents[0].SubjectID != string(s.Binding.UserID) ||
		s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) || len(plan.Audits) != 1 {
		return PhoneChangeIntent{}, nil, invalidPhoneChange()
	}
	if _, present := command.SessionToken(); !present {
		return PhoneChangeIntent{}, nil, invalidPhoneChange()
	}
	if audit := plan.Audits[0]; !audit.Required || audit.RetentionClass != "standard" || audit.EventType != "identity.identifier.change" {
		return PhoneChangeIntent{}, nil, invalidPhoneChange()
	}
	i, d, err := owner.PhoneChange(command)
	state := d.state()
	if err != nil || state == nil || state.directory == nil || state.directory.repository == nil || !state.directory.reuse.valid() || state.cascade == nil ||
		state.directory.profile != i.Change.NormalizationProfile || state.directory.version != i.Change.NormalizationVersion ||
		!slices.Contains(state.cascade.config.Reasons, i.Reason) || i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID ||
		string(i.Change.ID) != s.Binding.RecordID || plan.Lifecycle.BeforeVersion != i.Change.ExpectedIdentifierVersion ||
		plan.Lifecycle.AfterVersion != i.Change.ExpectedIdentifierVersion+1 || string(i.SendCommandID) != plan.OTP.ChallengeID || i.SendCommandID == s.Binding.CommandID {
		return PhoneChangeIntent{}, nil, invalidPhoneChange()
	}
	fields, err := PhoneChangeFields(i)
	if err != nil {
		return PhoneChangeIntent{}, nil, err
	}
	seen := make(map[string]bool, len(fields))
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "phone-change.") {
			continue
		}
		if seen[actual.Name] {
			return PhoneChangeIntent{}, nil, invalidPhoneChange()
		}
		found := false
		for _, expected := range fields {
			if actual.Name != expected.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if actual.Value.Kind != expected.Value.Kind || ea != nil || eb != nil || !bytes.Equal(a, b) {
				return PhoneChangeIntent{}, nil, invalidPhoneChange()
			}
			found, seen[actual.Name] = true, true
			break
		}
		if !found {
			return PhoneChangeIntent{}, nil, invalidPhoneChange()
		}
	}
	if len(seen) != len(fields) {
		return PhoneChangeIntent{}, nil, invalidPhoneChange()
	}
	return i, d, nil
}

// RequirePhoneChangeTarget locks the exact old verified target before OTP
// comparison or attempt debit, in the actual coordinator input-admission Work.
// Only this registered invocation can use it. It authenticates no proof or code
// and writes nothing; the native owner must repeat its other current fences.
func (w Work) RequirePhoneChangeTarget(ctx context.Context, owner PhoneChangeContributor, command identity.Command) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidPhoneChange())
	}
	b, registration, _, err := w.FeatureScope(owner)
	p := w.state.featurePreparationPlan
	if err != nil || p == nil || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != command || p.binding != b || registration.Operation != phoneChangeOperation() {
		return w.fail(ctx, invalidPhoneChange())
	}
	i, d, err := phoneChangeCommand(owner, command, p.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	matched := false
	domain := d.state()
	for _, entry := range p.contributors {
		if repository, ok := entry.contributor.(*Repository); ok && repository == domain.directory.repository {
			matched = true
		}
	}
	if !matched {
		return w.fail(ctx, invalidPhoneChange())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	if _, err = phoneChangeMutation(before, i, now); err != nil {
		return w.fail(ctx, err)
	}
	return checkIdentifierReuse(ctx, w, i.Change, domain.directory.reuse, now)
}

func phoneChangeMutation(before identity.IdentifierState, i PhoneChangeIntent, now time.Time) (identity.IdentifierMutation, error) {
	zero := identity.IdentifierMutation{}
	if _, err := PhoneChangeFields(i); err != nil {
		return zero, err
	}
	old := PhoneRemovalIntent{Change: i.Change, CanonicalNumber: i.PreviousNumber,
		NormalizationProfile: i.PreviousNormalizationProfile, NormalizationVersion: i.PreviousNormalizationVersion}
	if !phoneRemovalTarget(before, old) {
		return zero, identity.ForbiddenError{}
	}
	return identity.ApplyIdentifierChange(before, i.Change, now)
}

func preparePhoneChange(ctx context.Context, w Work, command identity.Command) error {
	p := w.state.execution.reservation.plan
	var owner PhoneChangeContributor
	var repository *Repository
	for _, entry := range p.contributors {
		if entry.descriptor == p.feature.Contributor {
			owner, _ = entry.contributor.(PhoneChangeContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repository, _ = entry.contributor.(*Repository)
		}
	}
	if owner == nil || repository == nil || w.state.phoneChange != nil {
		return w.fail(ctx, invalidPhoneChange())
	}
	i, d, err := phoneChangeCommand(owner, command, p.snapshot())
	if err != nil || d.state().directory.repository != repository {
		return w.fail(ctx, invalidPhoneChange())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	mutation, err := phoneChangeMutation(before, i, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	if err := checkIdentifierReuse(ctx, w, i.Change, d.state().directory.reuse, now); err != nil {
		return err
	}
	// Reuse the sole directory CAS/retirement and pending-cascade carrier.
	// The exact phone-change command above selects the workflow, not these
	// historical internal email/removal type names.
	domain := d.state()
	w.state.phoneChange = &emailRemovalProgress{intent: EmailRemovalIntent{Change: i.Change, Reason: i.Reason},
		domain: &EmailRemovalDomain{directory: &EmailAttachmentDomain{repository: repository, comparison: i.Change.NormalizationProfile, reuse: domain.directory.reuse}, cascade: domain.cascade},
		before: before, mutation: mutation, at: now}
	return nil
}

func applyPhoneChange(ctx context.Context, w Work) error {
	p := w.state.phoneChange
	if p == nil || p.applied || w.state.otpCommand == nil {
		return w.fail(ctx, invalidPhoneChange())
	}
	if err := w.state.execution.coordinator.runOTPExecution(ctx, w, *w.state.otpCommand, otpCheck); err != nil {
		return err
	}
	return applyIdentifierRemoval(ctx, w, p)
}

// Map only this Work's exact persisted successor for OTP's final fence. All
// other credential/status epochs and original evidence lifetimes stay fixed.
func otpPhoneChangeCredential(w Work, b identity.CommandBinding, original CredentialAdmission) (CredentialAdmission, error) {
	if w.state == nil || w.state.feature == nil || w.state.feature.Operation != phoneChangeOperation() || w.state.phoneChange == nil || !w.state.phoneChange.applied {
		return original, nil
	}
	p := w.state.phoneChange
	if w.state.binding != b || original.IdentifierAuthorityVersion != p.before.AuthorityVersion ||
		p.before.AuthorityVersion == ^uint64(0) || p.mutation.State.AuthorityVersion != p.before.AuthorityVersion+1 ||
		p.before.User.Version == ^uint64(0) || p.mutation.State.User.Version != p.before.User.Version+1 ||
		p.intent.Change.Action != identity.IdentifierReplaceVerifiedPhone ||
		p.intent.Change.TenantID != b.TenantID || p.intent.Change.UserID != b.UserID || string(p.intent.Change.ID) != b.RecordID {
		return CredentialAdmission{}, invalidPhoneChange()
	}
	original.IdentifierAuthorityVersion = p.mutation.State.AuthorityVersion
	return original, nil
}

func recoverPhoneChange(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || w.state.plan.lifecycle == nil || w.state.plan.lifecycle.BeforeVersion == 0 {
		return RecoveryUnknown, invalidPhoneChange()
	}
	// Earlier replacements preserve this ID and retire only their old value
	// versions. They must not prevent a later still-original command from voting
	// noncommit. A removal, contradictory equal/newer retirement or successor
	// never reconstructs historical success; the original journal owns it.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers i WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3 AND i.kind='phone' AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL AND i.version=$4 AND NOT EXISTS(SELECT 1 FROM identity.identifier_retirements r WHERE r.tenant_id=i.tenant_id AND r.identifier_id=i.identifier_id AND (r.removed OR r.record_version>=i.version)))`, string(b.TenantID), string(b.UserID), b.RecordID, w.state.plan.lifecycle.BeforeVersion)
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

// Format hides original phone numbers and correlated identity/command fields.
func (PhoneChangeIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneChangeIntent(redacted)"))
}

// MarshalJSON requires explicit protected persistence projection.
func (PhoneChangeIntent) MarshalJSON() ([]byte, error) { return nil, invalidPhoneChange() }

// Format redacts ordinary configuration formatting; exported startup fields
// remain sensitive and must not be enclosed in diagnostics that bypass methods.
func (PhoneChangeDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneChangeDomainConfig(redacted)"))
}

// MarshalJSON denies implicit key/configuration export.
func (PhoneChangeDomainConfig) MarshalJSON() ([]byte, error) { return nil, invalidPhoneChange() }

// Format hides borrowed native owners and retained key policies.
func (*PhoneChangeDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneChangeDomain(redacted)"))
}

// MarshalJSON denies implicit owner/key export.
func (*PhoneChangeDomain) MarshalJSON() ([]byte, error) { return nil, invalidPhoneChange() }
