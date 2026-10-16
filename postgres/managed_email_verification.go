package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ManagedEmailVerificationIntent freezes exact pending-address predecessors and
// original request. Link profiles select authenticated management provenance;
// the distinct OTP profile selects its independently issued OTP send command.
// Neither selection carries caller/proof authority.
// The initial managed link profile verifies a pending1/1 address without a primary
// swap, session issuance, email sender or signup reinterpretation.
type ManagedEmailVerificationIntent struct {
	Change                              identity.IdentifierChange
	CanonicalAddress, ComparisonProfile string
	RequestCommandID                    identity.CommandID
	Previous                            ManagedEmailPrevious
}

// ManagedEmailVerificationContributor owns original managed intent and current
// policy/factor/risk admission. Only the kernel writes identifier rows. The pure
// mapper must match every owned field and the exact enlisted domain; Apply and
// final checks must enforce the original proof/time without renewing authority.
type ManagedEmailVerificationContributor interface {
	FeatureCommitContributor
	ManagedEmailVerification(identity.Command) (ManagedEmailVerificationIntent, *EmailAttachmentDomain, error)
}

// ManagedEmailVerificationFields maps bounded initial pending verification to
// canonical native command fields. These are sensitive metadata, not authority.
// No normalization, cryptography, IO or callbacks occur; inputs remain immutable.
func ManagedEmailVerificationFields(i ManagedEmailVerificationIntent) ([]identity.FeatureField, error) {
	if i.Change.ExpectedIdentifierVersion != i.Change.ExpectedVerificationVersion {
		return nil, invalidEmailVerification()
	}
	change := i.Change
	if change.Action == identity.IdentifierVerifyPrimary {
		if i.Previous == (ManagedEmailPrevious{}) {
			return nil, invalidEmailVerification()
		}
		change.Action = identity.IdentifierVerify
	} else if i.Previous != (ManagedEmailPrevious{}) {
		return nil, invalidEmailVerification()
	}
	base := EmailVerificationIntent{Change: change, CanonicalAddress: i.CanonicalAddress, ComparisonProfile: i.ComparisonProfile, RegistrationCommandID: i.RequestCommandID}
	fields, err := emailVerificationFields(base, true)
	if err != nil || len(i.CanonicalAddress) > 254 {
		return nil, invalidEmailVerification()
	}
	for n := range fields {
		name := strings.TrimPrefix(fields[n].Name, "email-verification.")
		if name == "registration-command" {
			name = "request-command"
		}
		fields[n].Name = "managed-email-verification." + name
	}
	previous, err := previousEmailFields(i.Previous, i.Change.ID, "managed-email-verification.")
	if err != nil {
		return nil, err
	}
	return append(fields, previous...), nil
}

// Format redacts mailbox and correlated request/account metadata.
func (ManagedEmailVerificationIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ManagedEmailVerificationIntent(redacted)"))
}

// MarshalJSON denies implicit sensitive intent export.
func (ManagedEmailVerificationIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidEmailVerification()
}

func managedEmailVerificationCommand(p ManagedEmailVerificationContributor, c identity.Command, plan CommandPlan) (ManagedEmailVerificationIntent, *EmailAttachmentDomain, error) {
	s, ok := commandFeature(c)
	otp := otpEmailMutationOperation(s.Operation)
	if !ok || plan.Feature == nil || !managedEmailConfirmationOperation(s.Operation) && !otp || plan.Feature.Operation != s.Operation || plan.SubjectType != "identifier" || !otp && plan.Capability == nil || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion == 0 || plan.Lifecycle.BeforeVersion == ^uint64(0) || plan.Lifecycle.AfterVersion != plan.Lifecycle.BeforeVersion+1 {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	if s.Operation == otpEmailVerificationOperation() && validateOTPEmailVerificationScope(s, plan) != nil || s.Operation == otpEmailChangeOperation() && validateOTPEmailChangeScope(s, plan) != nil {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	i, d, err := p.ManagedEmailVerification(c)
	if err != nil || d == nil || d.repository == nil || !d.reuse.valid() || d.comparison != i.ComparisonProfile || i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID || string(i.Change.ID) != s.Binding.RecordID || i.RequestCommandID == s.Binding.CommandID || i.Change.ExpectedVerificationVersion != plan.Lifecycle.BeforeVersion {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	if (s.Operation == managedEmailChangeOperation() || s.Operation == otpEmailChangeOperation()) != (i.Change.Action == identity.IdentifierVerifyPrimary) {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	if s.Operation == otpEmailVerificationOperation() && (i.Change.Action != identity.IdentifierVerify || i.RequestCommandID != identity.CommandID(plan.OTP.ChallengeID)) {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	if s.Operation == otpEmailChangeOperation() && (!i.Previous.Primary || i.RequestCommandID == identity.CommandID(plan.OTP.ChallengeID)) {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	fields, err := ManagedEmailVerificationFields(i)
	if err != nil {
		return ManagedEmailVerificationIntent{}, nil, err
	}
	matched := 0
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "managed-email-verification.") {
			continue
		}
		found := false
		for _, expected := range fields {
			if actual.Name != expected.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if ea != nil || eb != nil || actual.Value.Kind != expected.Value.Kind || !bytes.Equal(a, b) {
				return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
			}
			found = true
			matched++
			break
		}
		if !found {
			return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
		}
	}
	if matched != len(fields) {
		return ManagedEmailVerificationIntent{}, nil, invalidEmailVerification()
	}
	return i, d, nil
}

type managedEmailVerificationProgress struct {
	intent             ManagedEmailVerificationIntent
	domain             *EmailAttachmentDomain
	before             identity.IdentifierState
	mutation           identity.IdentifierMutation
	at                 time.Time
	applied, finalized bool
}

func prepareManagedEmailVerification(ctx context.Context, w Work, c identity.Command) error {
	p := w.state.execution.reservation.plan
	var owner ManagedEmailVerificationContributor
	var repo *Repository
	for _, entry := range p.contributors {
		if entry.descriptor == p.feature.Contributor {
			owner, _ = entry.contributor.(ManagedEmailVerificationContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repo, _ = entry.contributor.(*Repository)
		}
	}
	if owner == nil || repo == nil || w.state.managedEmailVerification != nil {
		return w.fail(ctx, invalidEmailVerification())
	}
	i, d, err := managedEmailVerificationCommand(owner, c, p.snapshot())
	if err != nil || d.repository != repo {
		return w.fail(ctx, invalidEmailVerification())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	matched := false
	for _, a := range before.Identifiers {
		if a.ID == i.Change.ID {
			matched = a.Kind == identity.IdentifierEmail && a.CanonicalValue == i.CanonicalAddress && !a.Verified && !a.Primary
		}
	}
	if !matched {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	if i.Previous != (ManagedEmailPrevious{}) {
		if err := checkPreviousEmail(before, i.Previous, i.Change.ID); err != nil {
			return w.fail(ctx, err)
		}
	}
	mutation, err := identity.ApplyIdentifierChange(before, i.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	w.state.managedEmailVerification = &managedEmailVerificationProgress{intent: i, domain: d, before: before, mutation: mutation, at: now}
	return nil
}

func applyManagedEmailVerification(ctx context.Context, w Work) error {
	p := w.state.managedEmailVerification
	if p == nil || p.applied {
		return w.fail(ctx, invalidEmailVerification())
	}
	if otpEmailMutationOperation(w.state.feature.Operation) {
		if w.state.otpCommand == nil {
			return w.fail(ctx, invalidEmailVerification())
		}
		if err := w.state.execution.coordinator.runOTPExecution(ctx, w, *w.state.otpCommand, otpCheck); err != nil {
			return err
		}
	} else {
		if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
			return err
		}
	}
	if err := persistIdentifierMutation(ctx, w, w.state.binding, p.intent.Change, p.before, p.mutation, p.domain.reuse, p.at); err != nil {
		return err
	}
	p.applied = true
	return nil
}

func (c *Coordinator) finalizeManagedEmailVerification(w Work) error {
	p := w.state.managedEmailVerification
	if p == nil {
		return nil
	}
	if !p.applied || p.finalized {
		return w.fail(w.state.ctx, invalidEmailVerification())
	}
	if !otpEmailMutationOperation(w.state.feature.Operation) {
		if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
			return err
		}
	}
	p.finalized = true
	return nil
}

func recoverManagedEmailVerification(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	// A missing/changed target never proves noncommit. Negative evidence requires
	// the still-original pending record and no retirement/recreation history;
	// capability, audit, lifecycle and risk owners must independently agree.
	if w.state.plan.lifecycle == nil || w.state.plan.lifecycle.BeforeVersion == 0 {
		return RecoveryUnknown, invalidEmailVerification()
	}
	before := w.state.plan.lifecycle.BeforeVersion
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers i WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3 AND i.kind='email' AND i.version=$4 AND i.verification_version=$4 AND i.verification_state=1 AND NOT i.verified AND NOT i.is_primary AND NOT EXISTS(SELECT 1 FROM identity.identifier_retirements r WHERE r.tenant_id=i.tenant_id AND r.identifier_id=i.identifier_id))`, string(b.TenantID), string(b.UserID), b.RecordID, before)
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
