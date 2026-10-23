package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// FeaturePreparationContributor extends an exact registered native feature
// owner with original-request preparation. ValidateFeaturePreparation is pure,
// bounded schema/policy validation. AdmitFeaturePreparation borrows serial Work
// solely for current primary admission; it must not mutate domain state, stage
// effects, retain Work, perform network IO or generate secrets. Generation runs
// outside SQL only after the coordinator acknowledges the durable start marker.
// It returns bounded authenticated ciphertext, never plaintext credentials.
// RestoreFeaturePreparation authenticates that ciphertext against the complete
// original request and original generation, separately checks submitted bearer
// possession, and reconstructs the unchanged generated command and final plan.
// It must not generate, remap, renew authority/expiry or perform SQL/network IO.
// The same stable comparable owner handles every phase concurrently with
// invocation-local state. Final ApplyFeature still owns current authorization
// and atomic effects. No application-written workflow is required or permitted.
type FeaturePreparationContributor interface {
	FeatureInputAdmissionContributor
	ValidateFeaturePreparation(identity.Command, CommandPlan) error
	GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error)
	RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, error)
}

// FeaturePreparationAdmission is invocation-local state returned only by the
// exact registered native owner. Check is a bounded IO-free current validation
// of original admission facts; it must not renew them, call providers/stores,
// mutate state, or retain Work. Generate owns the original admitted request and
// embeds authenticated admission custody in its bounded encrypted output so a
// later native restore can recheck it without repeating external work. It runs
// outside SQL only after an acknowledged generation marker. Methods must obey
// cancellation; the owner must not share mutable invocation state across calls.
// This interface is neither an independently issued permission nor a journal.
type FeaturePreparationAdmission interface {
	Check(context.Context) error
	Generate(context.Context, uint64) ([]byte, error)
}

// FeatureAdmissionPreparationContributor opts a registered preparation owner
// into external admission. Prepare runs outside SQL only for journal-owned,
// never-started generation. It receives bounded context and the immutable
// original command; nil admission denies. Restore is bounded, IO-free native
// authentication of original retained ciphertext/generation, not provider or
// counter work, generation, or renewed admission. Both return independent
// invocation state for the original request. Busy, started-without-output and
// terminal replays call neither method. Legacy preparation owners are unchanged.
type FeatureAdmissionPreparationContributor interface {
	FeaturePreparationContributor
	PrepareFeatureAdmission(context.Context, identity.Command) (FeaturePreparationAdmission, error)
	RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error)
}

// Invocation-local custody is carried by the existing reservation, not by the
// shared registered owner or generic command fields. Provenance remains the
// original output generation when a later journal generation takes over.
type retainedFeaturePreparation struct {
	ciphertext []byte
	generation uint64
	admission  FeaturePreparationAdmission
}

// PrepareFeaturePreparationPlan validates and freezes an original generation
// declaration through the registered native preparation owner. Unlike ordinary
// PrepareCommandPlan, this may select original anonymous signup Secret/cookie
// custody before any generated verifier exists. Password and cookie intent are
// bounded and keyed by the existing claim codec; neither is persisted here.
//
// This performs no SQL, generation, provider work or reservation. Success is
// not flow possession, current admission or execution authority: submit the
// exact original command and returned declaration to ExecutePreparedFeature.
// Ordinary reservation still rejects original signup input. Returned plan data
// is independently owned. Keep shared Secrets alive through bounded execution
// and Destroy afterward. Invalid input returns zero plan and redacted error.
func (c *Coordinator) PrepareFeaturePreparationPlan(original identity.Command, declaration CommandPlan) (CommandPlan, error) {
	_, admitted, _, err := c.prepareFeaturePreparation(original, declaration)
	if err != nil {
		return CommandPlan{}, err
	}
	return admitted.snapshot(), nil
}

// FeaturePreparationOutput returns an owned copy of the original retained
// ciphertext and its original generation to the exact registered preparation
// owner during its synchronous final ApplyFeature invocation. This lets a
// stable native owner restore invocation-local custody without retaining shared
// request state or embedding ciphertext in smaller generic command fields.
//
// Ordinary execution, pre-generation admission, recovery, foreign participants,
// returned invocations, and unusable Work cannot read it. Ciphertext is not
// bearer possession, current authority or renewed expiry; the native owner must
// authenticate its existing envelope and separately recheck current admission.
// No SQL, encryption, callbacks or goroutines run. Use Work serially and do not
// retain it. Invalid access returns no bytes or generation and a redacted error.
func (w Work) FeaturePreparationOutput(p FeaturePreparationContributor) ([]byte, uint64, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil || !w.state.featureAttempted || w.state.execution == nil {
		return nil, 0, invalidWork()
	}
	e := w.state.execution
	if !e.coordinator.owns(w) || e.reservation.coordinator != e.coordinator {
		return nil, 0, invalidWork()
	}
	r := e.reservation
	if r.executionRequest == nil || r.preparation == nil || r.plan == nil || r.plan.registry != w.state.registry || r.plan.binding != w.state.binding || r.plan.feature == nil || *r.plan.feature != *w.state.feature {
		return nil, 0, invalidWork()
	}
	entry, err := e.coordinator.registry.selectFeatureOperation(*w.state.feature)
	if err != nil || !sameParticipant(entry.contributor, p) || r.preparation.generation == 0 || len(r.preparation.ciphertext) == 0 || len(r.preparation.ciphertext) > maximumPreparationCiphertext {
		return nil, 0, invalidWork()
	}
	return bytes.Clone(r.preparation.ciphertext), r.preparation.generation, nil
}

// ExecutePreparedFeature executes a native generated-output feature under its
// original code-free caller intent, using the existing claim/journal owner.
// declaration fixes feature, subject, mandatory audits and lifecycle before
// generation; the authenticated final plan may additionally enlist Delivery
// and exact anonymous-signup new-user verification issuance. Closed reset and
// magic-link consumption retain their original one-use input unchanged while
// generating the replacement/session. Other one-use profiles are rejected,
// not silently omitted. Explicit protected
// counters require CounterPreparationMigrationSource and a native current-check
// owner; their charge commits before generation and survives final rollback.
// Install PreparationMigrationSource before enabling this opt-in composition.
//
// Current native admission precedes the committed start marker. Entropy never
// runs under SQL or after a lost start acknowledgement. Started-without-output
// remains pending even after lease expiry; retained output resumes without
// regeneration or renewed provenance. Matching terminal replay returns original
// receipts without generation/restoration; changed intent conflicts. Only the
// exact registered owner may reconstruct final custody. The original request
// fingerprint remains unchanged and generated-command substitution remains
// rejected. Final execution rechecks native authority and commits all effects
// through Begin/ApplyFeature/Commit. Earlier deadlines win; panics/diagnostics
// are redacted and uncertain durable outcomes return UnknownCommitError.
// This trusted adapter seam is not a public authentication endpoint or proof.
func (c *Coordinator) ExecutePreparedFeature(ctx context.Context, original identity.Command, declaration CommandPlan) (result identity.CommandResult, err error) {
	return c.executePreparedFeature(ctx, nil, original, declaration)
}

// ExecutePreparedMFATOTPFeature uses original submitted intent for the sole
// journal and a separately validated counter-enriched command for native
// admission/generation/execution. Only the closed anonymous TOTP transformation
// is permitted. Full frozen-plan, counter and factor checks remain mandatory;
// no retry may replace original preparation or regenerate lost bearer custody.
func (c *Coordinator) ExecutePreparedMFATOTPFeature(ctx context.Context, original, prepared identity.Command, declaration CommandPlan) (identity.CommandResult, error) {
	f, ok := prepared.Feature()
	if !ok || f.Operation.OperationID != "identity.mfa.totp-verify" {
		return identity.CommandResult{}, invalidPreparation()
	}
	return c.executePreparedFeature(ctx, &original, prepared, declaration)
}

// ExecutePreparedMFARecoveryFeature retains original recovery/browser identity
// while executing the validated counter-enriched native declaration. Generation,
// atomic code consumption and session effects remain with the registered owner
// in the sole coordinator transaction. Replay cannot regenerate bearer custody
// or substitute original intent; uncertain outcomes require original recovery.
func (c *Coordinator) ExecutePreparedMFARecoveryFeature(ctx context.Context, original, prepared identity.Command, declaration CommandPlan) (identity.CommandResult, error) {
	f, ok := prepared.Feature()
	if !ok || f.Operation.OperationID != "identity.mfa.recovery-use" {
		return identity.CommandResult{}, invalidPreparation()
	}
	return c.executePreparedFeature(ctx, &original, prepared, declaration)
}

// ExecutePreparedMFAOTPFeature freezes the native mapped attempt before any
// session generation in the existing immutable preparation declaration. The
// original submitted code/browser defines journal identity; the exact OTP,
// child, counter and lifecycle owners retain atomic execution and recovery.
// Retained output never regenerates, terminal replay never compares again, and
// uncertain outcomes disclose no session. Restore frozen metadata before retry.
func (c *Coordinator) ExecutePreparedMFAOTPFeature(ctx context.Context, original, prepared identity.Command, declaration CommandPlan) (identity.CommandResult, error) {
	f, ok := prepared.Feature()
	if !ok || f.Operation.OperationID != "identity.mfa.otp-verify" || !validMFACompletionPlan(f.Binding, declaration) {
		return identity.CommandResult{}, invalidPreparation()
	}
	return c.executePreparedFeature(ctx, &original, prepared, declaration)
}

func (c *Coordinator) executePreparedFeature(ctx context.Context, claimSource *identity.Command, original identity.Command, declaration CommandPlan) (result identity.CommandResult, err error) {
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.maximumDuration <= 0 {
		return result, invalidPreparation()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	q, admitted, phase, err := c.prepareFeaturePreparation(original, declaration)
	if err != nil {
		return result, err
	}
	if claimSource != nil {
		q, admitted, err = c.originalMFAClaim(*claimSource, original, admitted)
		if err != nil {
			return result, err
		}
	}
	b := admitted.binding
	started := false
	defer func() {
		if recover() != nil {
			result, err = featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnavailableError{}
			if started {
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			}
		}
		if result.Outcome == identity.CommitOutcomeUnknown {
			err = identity.UnknownCommitError{CommandID: b.CommandID}
		}
	}()
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil || owner == ([16]byte{}) {
		return result, identity.UnavailableError{}
	}
	external, gated := phase.(FeatureAdmissionPreparationContributor)
	r, result, err := c.startFeaturePreparation(ctx, original, q, admitted, phase, owner, gated)
	if err != nil || r.journal.disposition != journalOwned {
		return result, err
	}
	started = true
	wire := r.output
	if gated {
		if r.generate {
			r.admission, err = external.PrepareFeatureAdmission(ctx, original)
		} else {
			r.admission, err = external.RestoreFeatureAdmission(ctx, original, r.outputGeneration, bytes.Clone(wire))
		}
		if err != nil || r.admission == nil || ctx.Err() != nil {
			return identity.CommandResult{}, preparationAdmissionError(ctx, err)
		}
		if err := checkPreparationAdmission(ctx, r.admission); err != nil {
			return identity.CommandResult{}, err
		}
		if r.generate {
			if err := c.markAdmittedPreparation(ctx, original, q, admitted, phase, r, owner); err != nil {
				return identity.CommandResult{}, err
			}
		}
	}
	if r.generate {
		if gated {
			if err := checkPreparationAdmission(ctx, r.admission); err != nil {
				return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
			}
			wire, err = r.admission.Generate(ctx, r.journal.generation)
		} else {
			wire, err = phase.GenerateFeaturePreparation(ctx, original, r.journal.generation)
		}
		if err != nil || ctx.Err() != nil || len(wire) == 0 || len(wire) > maximumPreparationCiphertext {
			return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
		}
		wire = bytes.Clone(wire)
		if err := c.retainFeaturePreparation(ctx, q, r.journal, owner, wire); err != nil {
			return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
		}
		r.outputGeneration = r.journal.generation
	}
	generated, final, err := phase.RestoreFeaturePreparation(ctx, original, r.outputGeneration, bytes.Clone(wire))
	if err != nil || ctx.Err() != nil || !preparationFinalDeclaration(b, admitted.snapshot(), final) {
		return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
	}
	executionRequest, snapshot, _, err := c.prepareRestoredFeature(b, generated, final)
	if err != nil {
		return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
	}
	reservation, err := c.attachFeaturePreparation(ctx, q, executionRequest, snapshot, r, owner, wire)
	if err != nil {
		if denied, ok := err.(preparationAttachmentDenied); ok {
			return denied.result, identity.ConflictError{}
		}
		return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), err
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err = c.ApplyFeature(ctx, w, generated)
	if err != nil {
		return c.Abort(w, err)
	}
	return c.Commit(w, result)
}

func (c *Coordinator) prepareRestoredFeature(b identity.CommandBinding, generated identity.Command, final CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	// Only this closed retained-preparation route may restore consuming OTP.
	// Ordinary command preparation remains closed to opaque code custody.
	if final.OTP != nil {
		if !(final.MFACompletion != nil && validMFACompletionPlan(b, final)) && !otpFactorPreparation(final) && !phoneResetConsumptionPlan(final) {
			return claimRequest{}, CommandPlan{}, nil, invalidPreparation()
		}
		return c.prepareOTPReservation(b, generated, final)
	}
	_, otp := generated.OneTimeCode()
	_, recovery := generated.RecoveryCode()
	if otp || recovery {
		// Factor custody is restored only through the retained native completion
		// owner. It is not an OTP challenge and must not acquire OTP phases.
		// prepareFeature still validates the native owner and complete command;
		// Apply must verify the factor under current locked authority.
		if c == nil || c.registry == nil || c.registry.state == nil || c.keys.current == 0 || !validMFACompletionPlan(b, final) {
			return claimRequest{}, CommandPlan{}, nil, invalidPreparation()
		}
		operation := final.Feature.Operation.OperationID
		if otp && operation != "identity.mfa.totp-verify" || recovery && operation != "identity.mfa.recovery-use" {
			return claimRequest{}, CommandPlan{}, nil, invalidPreparation()
		}
		spec, ok := commandFeature(generated)
		if !ok {
			return claimRequest{}, CommandPlan{}, nil, invalidPreparation()
		}
		entry, err := c.registry.selectFeatureOperation(*final.Feature)
		if err != nil {
			return claimRequest{}, CommandPlan{}, nil, invalidPreparation()
		}
		if _, ok := entry.contributor.(FeaturePreparationContributor); !ok {
			return claimRequest{}, CommandPlan{}, nil, invalidPreparation()
		}
		return c.prepareFeature(b, generated, spec, final)
	}
	return c.prepare(b, generated, final)
}

func (c *Coordinator) prepareFeaturePreparation(original identity.Command, p CommandPlan) (q claimRequest, admitted *admittedKernelPlan, phase FeaturePreparationContributor, err error) {
	defer func() {
		if recover() != nil {
			q, admitted, phase, err = claimRequest{}, nil, nil, invalidPreparation()
		}
	}()
	s, ok := commandFeature(original)
	if !ok || p.Feature == nil || p.Feature.Operation != s.Operation || p.Delivery != nil || preparationProtected(p) || p.SubjectType == "" || validateOrganizationInvitationOriginCommand(original, p) != nil {
		return q, nil, nil, invalidPreparation()
	}
	entry, e := c.registry.selectFeatureOperation(*p.Feature)
	if e != nil {
		return q, nil, nil, invalidPreparation()
	}
	phase, ok = entry.contributor.(FeaturePreparationContributor)
	if !ok || !sameParticipant(phase, phase) {
		return q, nil, nil, invalidPreparation()
	}
	q, e = prepareClaim(original, c.keys.retained[c.keys.current])
	if e != nil || !validClaim(q, c.keys) {
		return q, nil, nil, invalidPreparation()
	}
	fingerprint := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	wire, e := encodeFeaturePlan(s.Binding, fingerprint, p)
	ungenerated := ungeneratedMFAContinuation(p.MFAContinuation)
	if ungenerated {
		wire, e = encodeMFAContinuationPlanMode(s.Binding, fingerprint, p, true)
	}
	if e != nil {
		return q, nil, nil, invalidPreparation()
	}
	owned, e := decodeFeaturePlan(s.Binding, fingerprint, wire)
	if ungenerated {
		owned, e = decodeMFAContinuationPlanMode(s.Binding, fingerprint, wire, true)
	}
	if e != nil {
		return q, nil, nil, invalidPreparation()
	}
	admitted, e = c.registry.admitFeaturePlanMode(s.Binding, fingerprint, owned, true)
	if e != nil || phase.ValidateFeaturePreparation(original, admitted.snapshot()) != nil {
		return q, nil, nil, invalidPreparation()
	}
	if owned.MFAContinuation != nil && validateMFAContinuation(phase, original, admitted.snapshot()) != nil {
		return q, nil, nil, invalidPreparation()
	}
	if owned.MFACompletion != nil && validateMFACompletion(phase, original, admitted.snapshot()) != nil {
		return q, nil, nil, invalidPreparation()
	}
	if owned.OTP != nil && (otpReservationOwner(admitted) == nil || validateOTPAttempt(otpAttemptOwner(admitted), original, *owned.OTP) != nil) {
		return q, nil, nil, invalidPreparation()
	}
	if admitted.counters != nil {
		counter := counterAdmissionParticipant(admitted)
		if counter == nil || validateCommandCounters(counter, original, *admitted.counters) != nil {
			return q, nil, nil, invalidPreparation()
		}
	}
	return q, admitted, phase, nil
}

func preparationProtected(p CommandPlan) bool {
	phone := phoneResetConsumptionPlan(p)
	return p.IdentifierAdmission != nil || p.Capability != nil && !consumptionAuthenticationPreparation(p) || p.CapabilityIssuance != nil || p.OTP != nil && p.MFACompletion == nil && !otpFactorPreparation(p) && !phone || p.RiskEvidence != nil && !phone && !phoneResetRequestPreparation(p) || p.CaptchaEvidence != nil || p.CaptchaReplayReservation
}

// Only the original closed reset consumption plan may precede hash generation.
// It cannot add, replace or renew capability consumption in the final output.
// The plan codec and registry independently require the exact native owners.
func resetAuthenticationPreparation(p CommandPlan) bool {
	return phoneResetConsumptionPlan(p) || p.Feature != nil && p.Feature.Operation == credentialResetOperation() && p.Capability != nil && p.CommandCounters == nil
}

// The consuming magic-link declaration already contains the original verified
// one-use grant and charged counters. Preparation may generate the prospective
// session, never introduce or replace its authentication input. The ordinary
// closed plan codec and native owner still validate the complete envelope.
func consumptionAuthenticationPreparation(p CommandPlan) bool {
	return resetAuthenticationPreparation(p) || p.Feature != nil && p.Feature.Operation == magicLinkConsumeOperation() && p.Capability != nil && p.Capability.Purpose == "identity.magic-link.consume" && p.Capability.MaxUses == 1 || p.MFACompletion != nil && p.Feature != nil && mfaCompletionOperation(p.Feature.Operation) && p.Capability != nil && p.Capability.Purpose == "identity.mfa.complete" && p.Capability.MaxUses == 1
}

func preparationFinalDeclaration(b identity.CommandBinding, original, final CommandPlan) bool {
	if anonymousUpgradePreparationSelected(original) && (!validAnonymousUpgradePreparation(b, original) || !validAnonymousUpgradePreparation(b, final) || final.CapabilityIssuance == nil) {
		return false
	}
	if (original.OrganizationInvitationOrigin == nil) != (final.OrganizationInvitationOrigin == nil) || original.OrganizationInvitationOrigin != nil && *original.OrganizationInvitationOrigin != *final.OrganizationInvitationOrigin {
		return false
	}
	if original.Feature == nil || original.Lifecycle == nil || preparationProtected(original) || original.Delivery != nil {
		return false
	}
	if phoneResetRequestPreparation(original) && (final.CapabilityIssuance == nil || final.Delivery == nil || !validPhoneResetRequestIssuance(b, final)) {
		return false
	}
	if consumptionAuthenticationPreparation(original) {
		if !consumptionAuthenticationPreparation(final) || *original.Capability != *final.Capability || final.Delivery != nil || final.CapabilityIssuance != nil && original.MFAContinuation == nil {
			return false
		}
	} else if final.Capability != nil {
		return false
	}
	// Only closed native profiles add issuance, including the distinct internal
	// anonymous-upgrade preparation. That phase cannot consume or mutate a guest.
	// Their selected targets are admitted by distinct native transaction fences;
	// original admission stays issuance-free and cannot introduce consumption.
	withoutIssuance := final
	withoutIssuance.CapabilityIssuance = nil
	if final.CapabilityIssuance != nil && (!validCapabilityIssuancePlan(final.CapabilityIssuance) || final.MFAContinuation == nil && final.CapabilityIssuance.RegistrationUserID == "" && final.CapabilityIssuance.ResetRecipientUserID == "" && final.CapabilityIssuance.MagicLinkRecipientUserID == "" && !validManagedEmailIssuance(b, final) && !validOrganizationInvitationIssuance(b, final) && !phoneResetRequestPreparation(final) && !validAnonymousUpgradePreparation(b, final) || !validRegistrationIssuance(b, final) || !validResetRecipientIssuance(b, final) || !validMagicLinkRecipientIssuance(b, final) || !validMFAContinuationIssuance(b, final)) {
		return false
	}
	if final.Feature == nil || final.Lifecycle == nil || preparationProtected(withoutIssuance) || *original.Feature != *final.Feature || *original.Lifecycle != *final.Lifecycle || original.SubjectType != final.SubjectType || original.SignupAcceptance != final.SignupAcceptance || original.MagicLinkRequestAcceptance != final.MagicLinkRequestAcceptance || len(original.Audits) != len(final.Audits) {
		return false
	}
	if (original.CommandCounters == nil) != (final.CommandCounters == nil) || original.CommandCounters != nil && *original.CommandCounters != *final.CommandCounters {
		return false
	}
	if (original.RiskEvidence == nil) != (final.RiskEvidence == nil) || original.RiskEvidence != nil && *original.RiskEvidence != *final.RiskEvidence {
		return false
	}
	// Restoration may generate session material, but cannot change whether
	// consuming the original grant creates an account or its creation custody.
	if (original.MagicLinkRegistration == nil) != (final.MagicLinkRegistration == nil) || original.MagicLinkRegistration != nil && *original.MagicLinkRegistration != *final.MagicLinkRegistration {
		return false
	}
	if (original.PasskeyRegistration == nil) != (final.PasskeyRegistration == nil) || original.PasskeyRegistration != nil && *original.PasskeyRegistration != *final.PasskeyRegistration {
		return false
	}
	// Child signing may occur only after acknowledged original preparation.
	// It cannot introduce MFA, replace its primary proof or renew the exact
	// original challenge scope, including issue time and absolute expiry.
	if (original.MFAContinuation == nil) != (final.MFAContinuation == nil) {
		return false
	}
	if original.MFAContinuation != nil {
		a, z := original.MFAContinuation, final.MFAContinuation
		ungenerated := ungeneratedMFAContinuation(a)
		if !validMFAContinuationPlanMode(b, original, true) || !validMFAContinuationPlanMode(b, final, false) || final.CapabilityIssuance == nil || a.UserID != z.UserID || a.PolicyVersion != z.PolicyVersion || a.FactorVersion != z.FactorVersion || !ungenerated && *a != *z {
			return false
		}
	}
	if (original.MFACompletion == nil) != (final.MFACompletion == nil) || original.MFACompletion != nil && (*original.MFACompletion != *final.MFACompletion || !validMFACompletionPlan(b, original) || !validMFACompletionPlan(b, final)) {
		return false
	}
	addedEnrollmentOTP := original.OTP == nil && final.OTP != nil && otpFactorPreparation(original) && otpFactorPreparation(final)
	if !addedEnrollmentOTP && ((original.OTP == nil) != (final.OTP == nil) || original.OTP != nil && *original.OTP != *final.OTP) {
		return false
	}
	for i, a := range original.Audits {
		if a != final.Audits[i] {
			return false
		}
	}
	// Preserve the base exactly, then issuance, then optional delivery. The
	// existing plan codec and registry independently validate native ownership.
	expected := len(original.Contributors)
	if final.CapabilityIssuance != nil {
		expected++
	}
	if final.Delivery != nil {
		expected++
	}
	if addedEnrollmentOTP {
		expected++
	}
	if len(final.Contributors) != expected {
		return false
	}
	for i, d := range original.Contributors {
		if final.Contributors[i] != d {
			return false
		}
	}
	i := len(original.Contributors)
	if addedEnrollmentOTP {
		if final.Contributors[i] != otpDescriptor() {
			return false
		}
		i++
	}
	if final.CapabilityIssuance != nil {
		if final.Contributors[i] != final.CapabilityIssuance.Contributor {
			return false
		}
		i++
	}
	return final.Delivery == nil || final.Contributors[i] == final.Delivery.Contributor
}

func (c *Coordinator) startFeaturePreparation(ctx context.Context, original identity.Command, q claimRequest, p *admittedKernelPlan, phase FeaturePreparationContributor, owner [16]byte, external bool) (r preparationReservation, result identity.CommandResult, err error) {
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return r, result, readFailure(ctx, err)
	}
	defer func() {
		if rollbackErr := rollbackPreparation(tx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			r = preparationReservation{}
			result, err = featureOutcome(p.binding, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: p.binding.CommandID}
		}
	}()
	d, err := lockCommandClaim(ctx, tx, q, c.keys)
	if err != nil {
		return r, result, err
	}
	if d == claimConflict {
		return r, featureOutcome(p.binding, q.feature, identity.CommitOutcomeConflict, 0), identity.ConflictError{}
	}
	profile := int16(1)
	if external {
		profile = 2
	}
	if p.counters != nil {
		profile += 2
	}
	r, err = reservePreparationJournal(ctx, tx, q, d, owner, c.leaseDuration, profile)
	if err != nil {
		return r, result, err
	}
	if p.counters != nil {
		p, err = c.freezePreparationCounters(ctx, tx, q, p, original)
		if err != nil {
			return preparationReservation{}, result, err
		}
	}
	if r.journal.disposition != journalOwned {
		result = featureOutcome(p.binding, q.feature, identity.CommitOutcomeInProgress, r.journal.retryAfter)
		if r.journal.result != nil {
			result = *r.journal.result
		}
		return r, result, nil
	}
	if r.generate {
		if err := c.admitFeaturePreparation(ctx, tx, original, q, p, phase, r.journal, owner); err != nil {
			return preparationReservation{}, result, err
		}
	}
	denied, err := c.reserveCommandCounters(ctx, tx, original, q, p, r.journal, owner)
	if err != nil {
		return preparationReservation{}, result, err
	}
	if denied {
		// A denied attempt has no generated command. Persist its original frozen
		// plan so ordinary receipt queries and recovery retain complete evidence.
		if _, err := c.freezePlanMode(ctx, tx, p.binding, q, claimNew, p.snapshot(), true); err != nil {
			return preparationReservation{}, result, err
		}
	}
	if r.generate && !denied {
		if err := c.advanceOAuthContinuationPreparation(ctx, tx, original, q, p, phase, r.journal, owner, external); err != nil {
			return preparationReservation{}, result, err
		}
	}
	if r.generate && !external && !denied {
		if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
			return preparationReservation{}, result, err
		}
	}
	if err := c.commitPreparation(ctx, tx); err != nil {
		return preparationReservation{}, featureOutcome(p.binding, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: p.binding.CommandID}
	}
	if denied {
		return preparationReservation{}, featureOutcome(p.binding, q.feature, identity.CommitOutcomeNotCommitted, 0), identity.ForbiddenError{}
	}
	return r, featureOutcome(p.binding, q.feature, identity.CommitOutcomeInProgress, c.leaseDuration), nil
}

func (c *Coordinator) admitFeaturePreparation(ctx context.Context, tx pgx.Tx, original identity.Command, q claimRequest, p *admittedKernelPlan, phase FeaturePreparationContributor, j journalReservation, owner [16]byte) (err error) {
	fence, err := beginJournal(ctx, tx, q, c.keys, j, owner)
	if err != nil {
		return err
	}
	w, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return err
	}
	defer func() {
		invalidateWork(w)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	w.state.registry = c.registry.state
	if err := p.bindWork(w); err != nil {
		return err
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return err
	}
	return c.invokeFeatureInputAdmission(ctx, w, original, p)
}

func (c *Coordinator) retainFeaturePreparation(ctx context.Context, q claimRequest, j journalReservation, owner [16]byte, wire []byte) error {
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return readFailure(ctx, err)
	}
	defer rollbackPreparation(tx)
	d, err := lockCommandClaim(ctx, tx, q, c.keys)
	if err != nil {
		return err
	}
	if d != claimReplay {
		return identity.ConflictError{}
	}
	if err := retainJournalPreparation(ctx, tx, q, j, owner, wire); err != nil {
		return err
	}
	return c.commitPreparation(ctx, tx)
}

func (c *Coordinator) attachFeaturePreparation(ctx context.Context, original, generated claimRequest, final CommandPlan, r preparationReservation, owner [16]byte, wire []byte) (Reservation, error) {
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reservation{}, readFailure(ctx, err)
	}
	defer rollbackPreparation(tx)
	if _, err := beginJournal(ctx, tx, original, c.keys, r.journal, owner); err != nil {
		return Reservation{}, err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(original.commandID))
	var stored, plan []byte
	var generation string
	if err := tx.QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,command_plan FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3`, id, string(original.tenant), original.purpose).Scan(&stored, &generation, &plan); err != nil {
		return Reservation{}, readFailure(ctx, err)
	}
	if !bytes.Equal(stored, wire) || !preparationGeneration(generation, r.outputGeneration) {
		return Reservation{}, identity.ConflictError{}
	}
	d := claimReplay
	if plan == nil {
		d = claimNew
	}
	// The legacy accessor deliberately rejects password custody. Preserve the
	// explicitly admitted native variant instead of freezing a zero binding.
	if generated.source == nil {
		return Reservation{}, invalidPreparation()
	}
	s, ok := commandFeature(*generated.source)
	if !ok {
		return Reservation{}, invalidPreparation()
	}
	admitted, err := c.freezePlan(ctx, tx, s.Binding, original, d, final)
	if err != nil {
		return Reservation{}, err
	}
	if admitted.otp != nil {
		if admitted.mfaCompletion == nil && !otpFactorPreparation(admitted.snapshot()) && !phoneResetConsumptionPlan(admitted.snapshot()) || generated.source == nil {
			return Reservation{}, invalidPreparation()
		}
		otpJournal := r.journal
		// A journal-only predecessor has never attached a reservation. Once an
		// attachment exists, transfer its exact generation rather than compare
		// or charge the original opaque submission again.
		if plan == nil {
			otpJournal.previousGeneration = 0
		}
		if plan == nil && (otpFactorPreparation(admitted.snapshot()) || validMFACompletionPlan(admitted.binding, admitted.snapshot()) || phoneResetConsumptionPlan(admitted.snapshot())) {
			// Reuse the native counted-denial phase in this same attachment
			// transaction before any consuming participant is reserved. A correct
			// precheck rolls back; a wrong submission retains debit/audit/terminal
			// result without reserving the child's remaining legitimate authority.
			counted, err := tx.Begin(ctx)
			if err != nil {
				return Reservation{}, readFailure(ctx, err)
			}
			choice, result, err := c.recordCountedAttempt(ctx, counted, *generated.source, original, admitted, otpJournal, owner, false, false, true)
			if err != nil {
				if rollbackPreparation(counted) != nil {
					return Reservation{}, identity.UnavailableError{}
				}
				// Original native authority can disappear while preparation is
				// outside locks. A definitive first-attachment denial has reached
				// neither domain execution nor any retained OTP reservation. Keep
				// its frozen original plan/audit/terminal receipt instead of leaving
				// an unrecoverable journal with no final attachment. Never release
				// the competing command's OTP or classify a failed acknowledgement.
				var forbidden identity.ForbiddenError
				var conflict identity.ConflictError
				if ctx.Err() == nil && (errors.As(err, &forbidden) || errors.As(err, &conflict)) {
					result, failure := c.denyPreparationAttachment(ctx, tx, original, admitted, r.journal, owner)
					if failure != nil {
						return Reservation{}, failure
					}
					if failure := c.commitPreparation(ctx, tx); failure != nil {
						return Reservation{}, failure
					}
					return Reservation{}, preparationAttachmentDenied{result: result}
				}
				return Reservation{}, err
			}
			if choice == OTPAttemptUnchanged {
				if err := rollbackPreparation(counted); err != nil {
					return Reservation{}, readFailure(ctx, err)
				}
			} else if choice == OTPAttemptDenied {
				if err := counted.Commit(ctx); err != nil {
					return Reservation{}, readFailure(ctx, err)
				}
				if err := c.commitPreparation(ctx, tx); err != nil {
					return Reservation{}, err
				}
				return Reservation{}, preparationAttachmentDenied{result: result}
			} else {
				_ = rollbackPreparation(counted)
				return Reservation{}, invalidPreparation()
			}
		}
	}
	if admitted.otp != nil || admitted.risk != nil || admitted.capability != nil {
		// Denial must roll back the entire consuming prefix, not just its last
		// participant. Otherwise a rejected command can strand the child's
		// one-use reservation, or retain OTP after a later child conflict.
		participants, err := tx.Begin(ctx)
		if err != nil {
			return Reservation{}, readFailure(ctx, err)
		}
		journal := r.journal
		if plan == nil {
			// A journal-only predecessor has no committed consuming reservation.
			journal.previousGeneration = 0
		}
		if admitted.otp != nil {
			err = c.reserveOTP(ctx, participants, *generated.source, original, admitted, journal, owner)
		}
		if err == nil && admitted.risk != nil {
			// The counted conjunction above must finish before any evidence use.
			// Keep this reservation in the same rollback prefix as OTP/capability;
			// later failure cannot strand a legitimate remaining one-use proof.
			err = c.reserveRisk(ctx, participants, original, admitted, journal, owner)
		}
		if err == nil && admitted.capability != nil {
			// Preserve capability-last enlistment for the joined OTP profile.
			err = c.reserveCapability(ctx, participants, original, admitted, journal, owner)
		}
		if err != nil {
			if rollbackPreparation(participants) != nil {
				return Reservation{}, identity.UnavailableError{}
			}
			var forbidden identity.ForbiddenError
			var conflict identity.ConflictError
			definitive := errors.As(err, &conflict) || admitted.otp != nil && errors.As(err, &forbidden)
			if plan == nil && ctx.Err() == nil && definitive {
				result, failure := c.denyPreparationAttachment(ctx, tx, original, admitted, r.journal, owner)
				if failure != nil {
					return Reservation{}, failure
				}
				if failure := c.commitPreparation(ctx, tx); failure != nil {
					return Reservation{}, failure
				}
				return Reservation{}, preparationAttachmentDenied{result: result}
			}
			return Reservation{}, err
		}
		if err := participants.Commit(ctx); err != nil {
			return Reservation{}, readFailure(ctx, err)
		}
	}
	if err := c.commitPreparation(ctx, tx); err != nil {
		return Reservation{}, err
	}
	return Reservation{state: &reservationState{coordinator: c, request: original, executionRequest: &generated, preparation: &retainedFeaturePreparation{ciphertext: bytes.Clone(wire), generation: r.outputGeneration, admission: r.admission}, plan: admitted, journal: r.journal, owner: owner}}, nil
}

// External work sees an acknowledged existing journal lease, never SQL locks.
// Reacquire and check that same owner and current native authority afterwards.
func (c *Coordinator) markAdmittedPreparation(ctx context.Context, original identity.Command, q claimRequest, p *admittedKernelPlan, phase FeaturePreparationContributor, r preparationReservation, owner [16]byte) (err error) {
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return readFailure(ctx, err)
	}
	defer func() {
		if e := rollbackPreparation(tx); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
			err = identity.UnknownCommitError{CommandID: q.commandID}
		}
	}()
	d, err := lockCommandClaim(ctx, tx, q, c.keys)
	if err != nil {
		return err
	}
	if d != claimReplay {
		return identity.ConflictError{}
	}
	if err := c.admitFeaturePreparation(ctx, tx, original, q, p, phase, r.journal, owner); err != nil {
		return err
	}
	if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
		return err
	}
	if err := checkPreparationAdmission(ctx, r.admission); err != nil {
		return err
	}
	if err := c.commitPreparation(ctx, tx); err != nil {
		return identity.UnknownCommitError{CommandID: q.commandID}
	}
	return nil
}

func preparationAdmissionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return identity.UnavailableError{}
	}
	_, _, _, safe := abortClassification(err)
	return safe
}

func checkPreparationAdmission(ctx context.Context, a FeaturePreparationAdmission) (err error) {
	if ctx == nil {
		return invalidPreparation()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil {
		return identity.UnavailableError{}
	}
	defer func() {
		if recover() != nil {
			err = preparationAdmissionError(ctx, identity.UnavailableError{})
		}
	}()
	if err := a.Check(ctx); err != nil {
		return preparationAdmissionError(ctx, err)
	}
	return ctx.Err()
}

func (c *Coordinator) checkPreparedAdmission(w Work) error {
	if !c.owns(w) || w.state.execution == nil {
		return invalidWork()
	}
	p := w.state.execution.reservation.preparation
	plan := w.state.execution.reservation.plan
	if plan != nil && plan.feature != nil && (credentialResetSelected(plan.feature.Operation) || plan.feature.Operation == magicLinkConsumeOperation() || plan.mfaCompletion != nil) && plan.counters == nil {
		if p == nil || p.admission == nil || p.generation == 0 || len(p.ciphertext) == 0 || len(p.ciphertext) > maximumPreparationCiphertext || w.state.execution.reservation.executionRequest == nil {
			return invalidPreparation()
		}
	}
	if p == nil || p.admission == nil {
		return nil
	}
	return checkPreparationAdmission(w.state.ctx, p.admission)
}

// No acknowledgement error is interpreted as rollback. Rollback is cleanup
// only and cannot authorize another generation after a possible start commit.
func rollbackPreparation(tx pgx.Tx) error {
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	return tx.Rollback(ctx)
}

func (c *Coordinator) commitPreparation(ctx context.Context, tx pgx.Tx) error {
	if c.preparationCommit != nil {
		return c.preparationCommit(ctx, tx)
	}
	return tx.Commit(ctx)
}

func preparationGeneration(raw string, expected uint64) bool {
	return expected != 0 && raw == strconv.FormatUint(expected, 10)
}
