package postgres

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PrepareCommandCounters adds a closed native counter projection to an existing
// protected feature command. Subject is trusted server-resolved input, not an
// HTTP request: subject/actor/resource must equal the command's canonical binding.
// PrimaryTime is supplied primary UTC microsecond time; reservation rechecks it
// without renewal. Raw network/session values stay only in the opaque command,
// not persisted columns or the frozen plan. This pure method grants no allowance,
// authorization or commitment. The feature owner must validate its own schema
// including these reserved fields. Zero/disabled repository fails redacted.
func (r *Repository) PrepareCommandCounters(c identity.Command, subject risk.Subject, primaryTime time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	return r.prepareCommandCounters(c, subject, "", "", primaryTime)
}

// PrepareVerificationCommandCounters selects only the core's sessionless
// registration-link lane. The native email owner must authenticate capabilityID
// and subject.User from the original signed grant, preserve its exact command
// and callback intent, and match this ID to its capability consumption plan.
// Only identity.email.verification-confirm accepts this profile; no session is
// fabricated. Network is trusted transport input. Install the separately
// allocated VerificationCounterMigrationSource before reservation. This pure
// preparation performs no IO, grants no proof validation/allowance and returns
// zero on error. Existing PrepareCommandCounters retains session semantics.
func (r *Repository) PrepareVerificationCommandCounters(c identity.Command, subject risk.Subject, capabilityID string, primaryTime time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	s, ok := c.Feature()
	if !ok || s.Operation.Owner != "identity/email" || s.Binding.OperationID != "identity.email.verification-confirm" || capabilityID == "" {
		return identity.Command{}, identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	return r.prepareCommandCounters(c, subject, capabilityID, "", primaryTime)
}

// PrepareEmailChangeCommandCounters selects only the managed-v1 change-confirm
// profile. Signed original user/grant and trusted network must be conserved.
// Install EmailChangeCounterMigrationSource; no live session is inferred. This
// is pure preparation, not allowance, proof authentication or consumption.
func (r *Repository) PrepareEmailChangeCommandCounters(c identity.Command, subject risk.Subject, capabilityID string, primaryTime time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	s, ok := c.Feature()
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-confirm", SchemaID: "identity.email.change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if !ok || s.Operation != op || capabilityID == "" {
		return identity.Command{}, identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	return r.prepareCommandCounters(c, subject, capabilityID, "", primaryTime)
}

// PrepareMFACompletionCommandCounters selects only anonymous native TOTP/OTP/recovery login
// completion. It binds the signed continuation subject and child plan without
// inventing an authenticated session or changing command user ownership.
// Preserve opaque code/cookie custody. The actual reservation/current checks
// compare this projection to sealed coordinator-owned completion scope; pure
// preparation alone grants no factor, proof, allowance or mutation authority.
func (r *Repository) PrepareMFACompletionCommandCounters(c identity.Command, subject risk.Subject, child identitypostgres.CapabilityPlan, completion identitypostgres.MFACompletionPlan, at time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	s, ok := c.Feature()
	_, code := c.OneTimeCode()
	if ok && s.Operation.OperationID == "identity.mfa.recovery-use" {
		_, code = c.RecoveryCode()
	}
	_, cookie := c.PreAuthCookie()
	if !ok || !anonymousMFACounter(s) || !code || !cookie || subject.User != string(completion.UserID) || completion.UserID == "" || child.Purpose != "identity.mfa.complete" || child.MaxUses != 1 || child.CapabilityID != string(completion.ID) || completion.ScopeDigest == ([32]byte{}) || completion.PolicyVersion == 0 || completion.FactorVersion == 0 || completion.ContinuationVersion == 0 {
		return identity.Command{}, identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	return r.prepareCommandCounters(c, subject, child.CapabilityID, completion.UserID, at)
}

// PrepareMFALoginSendCommandCounters selects the closed anonymous OTP-send
// lane. The registered native MFA owner must authenticate the resolved user,
// original signed child, confirmed factor and consumed-primary browser before
// charging. Reservation and current checks compare this projection to that
// exact owner's source; pure preparation is not authentication or allowance.
// The browser dimension uses the immutable original AnonymousFlowID, never a
// new child or a fabricated session. Original cookie custody is retained and
// journal UserID remains empty. Cancellation/IO and mutation belong to execution.
func (r *Repository) PrepareMFALoginSendCommandCounters(c identity.Command, subject risk.Subject, at time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	s, ok := c.Feature()
	_, cookie := c.PreAuthCookie()
	_, code := c.OneTimeCode()
	_, recovery := c.RecoveryCode()
	if !ok || !anonymousMFASendCounter(s) || !cookie || code || recovery || subject.User == "" {
		return identity.Command{}, identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	return r.prepareCommandCounters(c, subject, "", identity.UserID(subject.User), at)
}

func anonymousMFASendCounter(s identity.FeatureCommandSpec) bool {
	if s.Operation != (identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}) || s.Binding.UserID != "" || s.Binding.AnonymousFlowID == "" {
		return false
	}
	_, err := identity.ParseCommandID(s.Binding.RecordID)
	return err == nil
}

func anonymousMFACounter(s identity.FeatureCommandSpec) bool {
	operation, schema := "identity.mfa.totp-verify", "mfa-totp-verify"
	if s.Operation.OperationID == "identity.mfa.recovery-use" {
		operation, schema = "identity.mfa.recovery-use", "mfa-recovery-use"
	} else if s.Operation.OperationID == "identity.mfa.otp-verify" {
		operation, schema = "identity.mfa.otp-verify", "mfa-otp-verify"
	}
	return s.Operation == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: operation, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}) && s.Binding.UserID == "" && s.Binding.AnonymousFlowID != "" && s.Binding.RecordID == ""
}

// Upgrade authenticates a permanent target but disposes the distinct guest.
// Its credential-mutation budget must stay on that original guest and session,
// not move to the target when command ownership changes. This exact tuple does
// not admit arbitrary cross-subject mutation or a caller-authored resolution.
func anonymousUpgradeCounter(s identity.FeatureCommandSpec) bool {
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	_, err := identity.ParseSubjectID(s.Binding.RecordID)
	return s.Operation == op && s.Binding.ValidateFor(op) == nil && s.Binding.RecordID != string(s.Binding.UserID) && string(s.Binding.ActorID) == string(s.Binding.UserID) && err == nil
}

func (r *Repository) prepareCommandCounters(c identity.Command, subject risk.Subject, capabilityID string, resolvedUser identity.UserID, primaryTime time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	fail := func() (identity.Command, identitypostgres.CommandCounterPlan, error) {
		return identity.Command{}, identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	s, ok := counterCommandFeature(c)
	if !ok || r == nil || r.counters == nil {
		return fail()
	}
	for _, f := range s.Fields {
		if strings.HasPrefix(f.Name, "counter.") {
			return fail()
		}
	}
	scope := risk.Context{Tenant: string(s.Binding.TenantID), Operation: risk.Action(s.Binding.OperationID), Attempt: string(s.Binding.CommandID)}
	admission, e := r.counters.Policy.Admit(scope.Operation)
	if e != nil {
		return fail()
	}
	user := string(s.Binding.UserID)
	if s.Operation.OperationID == "identity.anonymous.upgrade" {
		if !anonymousUpgradeCounter(s) {
			return fail()
		}
		user = s.Binding.RecordID
	}
	if admission.Profile.Class == risk.CredentialMutation && subject.User != user && (resolvedUser == "" || subject.User != string(resolvedUser)) || admission.Profile.Class == risk.Privileged && (subject.Actor != string(s.Binding.ActorID) || subject.Resource != s.Binding.RecordID) {
		return fail()
	}
	boundID := capabilityID
	if resolvedUser != "" && anonymousMFASendCounter(s) {
		boundID = s.Binding.AnonymousFlowID
	}
	native, e := prepareNativeCounter(r.counterPolicy, scope, subject, boundID, primaryTime)
	if e != nil {
		return fail()
	}
	b := native.Bindings()
	if b.PolicyVersion != r.policy {
		return fail()
	}
	versions := make([]byte, 4*len(b.Targets[0].Keys))
	for i, k := range b.Targets[0].Keys {
		binary.BigEndian.PutUint32(versions[i*4:], k.Version)
	}
	s.Fields = append(s.Fields, textField("counter.network", subject.Network), textField("counter.session", subject.Session), identity.FeatureField{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: primaryTime}}, identity.FeatureField{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: versions}})
	if capabilityID != "" {
		s.Fields = append(s.Fields, textField("counter.capability", capabilityID))
	}
	if resolvedUser != "" {
		s.Fields = append(s.Fields, textField("counter.subject", string(resolvedUser)))
	}
	var mapped identity.Command
	if resolvedUser != "" && anonymousMFASendCounter(s) {
		cookie, _ := c.PreAuthCookie()
		mapped, e = identity.NewFeaturePreAuthCommand(s, cookie)
	} else if resolvedUser != "" {
		code, _ := c.OneTimeCode()
		cookie, _ := c.PreAuthCookie()
		mapped, e = identity.NewFeatureOneTimeCodePreAuthCommand(s, code, cookie)
		if s.Operation.OperationID == "identity.mfa.recovery-use" {
			recovery, _ := c.RecoveryCode()
			mapped, e = identity.NewFeatureRecoveryCodePreAuthCommand(s, recovery, cookie)
		}
	} else if hash, bearer, proof, authenticated := c.PasswordChangeCustody(); authenticated {
		// Rebuild the disjoint variant without dropping or renewing any original
		// custody. Counter preparation itself authenticates neither the bearer
		// nor the proof; the protected native feature remains their authority.
		mapped, e = identity.NewFeaturePasswordChangeCommand(s, hash, bearer, proof)
	} else if bearer, has := c.SessionToken(); has {
		// Authenticated feature counters retain the original borrowed bearer.
		// A scalar-only rebuild would strip the owning workflow's possession
		// custody before its protected primary admission can run.
		mapped, e = identity.NewFeatureSessionCommand(s, bearer)
	} else {
		mapped, e = identity.NewFeatureCommand(s)
	}
	if e != nil {
		return fail()
	}
	plan, e := counterPlan(b)
	if e != nil {
		return fail()
	}
	return mapped, plan, nil
}

// Preserve existing Feature admission and add only the explicit authenticated
// change profile. The separate hash-only profile remains closed.
func counterCommandFeature(c identity.Command) (identity.FeatureCommandSpec, bool) {
	if s, ok := c.Feature(); ok {
		return s, true
	}
	return c.PasswordChangeFeature()
}
func counterPlan(b risk.CounterBinding) (identitypostgres.CommandCounterPlan, error) {
	raw, e := hex.DecodeString(b.Fingerprint)
	if e != nil || len(raw) != 32 {
		return identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	p := identitypostgres.CommandCounterPlan{PolicyVersion: b.PolicyVersion}
	copy(p.Fingerprint[:], raw)
	return p, nil
}

type restoredCounter struct {
	command      risk.CounterCommand
	policy       risk.CommandCounterPolicy
	current      risk.CounterBinding
	scope        risk.Context
	subject      risk.Subject
	capabilityID string
}

func prepareNativeCounter(p risk.CommandCounterPolicy, scope risk.Context, subject risk.Subject, capabilityID string, at time.Time) (risk.CounterCommand, error) {
	if capabilityID != "" {
		if scope.Operation == "identity.email.change-confirm" {
			return p.PrepareEmailChange(scope, subject, capabilityID, at)
		}
		if scope.Operation == "identity.mfa.otp-send" {
			return p.PrepareMFALoginSend(scope, subject, capabilityID, at)
		}
		if nativeMFACounterAction(scope.Operation) {
			return p.PrepareMFACompletion(scope, subject, capabilityID, at)
		}
		return p.PrepareVerification(scope, subject, capabilityID, at)
	}
	return p.Prepare(scope, subject, at)
}

func (n restoredCounter) validateAt(at time.Time) error {
	if n.capabilityID != "" {
		if n.scope.Operation == "identity.email.change-confirm" {
			return n.policy.ValidateEmailChange(n.command, n.scope, n.subject, n.capabilityID, at)
		}
		if n.scope.Operation == "identity.mfa.otp-send" {
			return n.policy.ValidateMFALoginSend(n.command, n.scope, n.subject, n.capabilityID, at)
		}
		if nativeMFACounterAction(n.scope.Operation) {
			return n.policy.ValidateMFACompletion(n.command, n.scope, n.subject, n.capabilityID, at)
		}
		return n.policy.ValidateVerification(n.command, n.scope, n.subject, n.capabilityID, at)
	}
	return n.policy.Validate(n.command, n.scope, n.subject, at)
}

func nativeMFACounterAction(action risk.Action) bool {
	return action == "identity.mfa.totp-verify" || action == "identity.mfa.otp-verify" || action == "identity.mfa.recovery-use"
}

// ValidateCommandCounters reconstructs exact native scope and its original
// retained-key projection without IO. Historical key subsets remain decodable
// during rotation, but only current complete history admits a new charge.
func (r *Repository) ValidateCommandCounters(c identity.Command, p identitypostgres.CommandCounterPlan) error {
	_, e := r.restoreCounter(c, p)
	return e
}
func (r *Repository) restoreCounter(c identity.Command, p identitypostgres.CommandCounterPlan) (restoredCounter, error) {
	fail := func() (restoredCounter, error) { return restoredCounter{}, risk.ErrInvalidCounterCommand }
	s, ok := counterCommandFeature(c)
	if !ok || r == nil || r.counters == nil || p.PolicyVersion != r.policy {
		return fail()
	}
	if anonymousMFASendCounter(s) {
		_, cookie := c.PreAuthCookie()
		_, code := c.OneTimeCode()
		_, recovery := c.RecoveryCode()
		if !cookie || code || recovery {
			return fail()
		}
	}
	scope := risk.Context{Tenant: string(s.Binding.TenantID), Operation: risk.Action(s.Binding.OperationID), Attempt: string(s.Binding.CommandID)}
	a, e := r.counters.Policy.Admit(scope.Operation)
	if e != nil {
		return fail()
	}
	subject := risk.Subject{}
	switch a.Profile.Class {
	case risk.CredentialMutation:
		subject.User = string(s.Binding.UserID)
		if s.Operation.OperationID == "identity.anonymous.upgrade" {
			if !anonymousUpgradeCounter(s) {
				return fail()
			}
			subject.User = s.Binding.RecordID
		}
	case risk.Privileged:
		subject.Actor = string(s.Binding.ActorID)
		subject.Resource = s.Binding.RecordID
	default:
		return fail()
	}
	var at time.Time
	var versions []byte
	var capabilityID string
	count := 0
	for _, f := range s.Fields {
		if !strings.HasPrefix(f.Name, "counter.") {
			continue
		}
		count++
		switch f.Name {
		case "counter.network":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			subject.Network = f.Value.Text
		case "counter.session":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			subject.Session = f.Value.Text
		case "counter.capability":
			if f.Value.Kind != identity.FeatureText || f.Value.Text == "" || s.Operation.Owner != "identity/email" && !anonymousMFACounter(s) {
				return fail()
			}
			capabilityID = f.Value.Text
		case "counter.subject":
			if !anonymousMFACounter(s) && !anonymousMFASendCounter(s) || f.Value.Kind != identity.FeatureText || f.Value.Text == "" {
				return fail()
			}
			subject.User = f.Value.Text
		case "counter.prepared-at":
			if f.Value.Kind != identity.FeatureTime {
				return fail()
			}
			at = f.Value.Time
		case "counter.key-versions":
			if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) < 4 || len(f.Value.Bytes) > 16 || len(f.Value.Bytes)%4 != 0 {
				return fail()
			}
			versions = f.Value.Bytes
		default:
			return fail()
		}
	}
	expectedCount := 4
	if capabilityID != "" {
		expectedCount = 5
	}
	if anonymousMFACounter(s) {
		if capabilityID == "" || subject.User == "" {
			return fail()
		}
		expectedCount = 6
	}
	if anonymousMFASendCounter(s) {
		if capabilityID != "" || subject.User == "" {
			return fail()
		}
		expectedCount = 5
		capabilityID = s.Binding.AnonymousFlowID
	}
	if count != expectedCount {
		return fail()
	}
	current, e := prepareNativeCounter(r.counterPolicy, scope, subject, capabilityID, at)
	if e != nil {
		return fail()
	}
	b := current.Bindings()
	var selected []risk.CounterDigestKey
	for off := 0; off < len(versions); off += 4 {
		version := binary.BigEndian.Uint32(versions[off:])
		if version == 0 || off > 0 && binary.BigEndian.Uint32(versions[off-4:]) <= version {
			return fail()
		}
		found := false
		for i, k := range b.Targets[0].Keys {
			if k.Version == version {
				selected = append(selected, r.counters.Keys[i])
				found = true
				break
			}
		}
		if !found {
			return fail()
		}
	}
	cfg := risk.CommandCounterPolicyConfig{Policy: r.counters.Policy, Keys: selected}
	policy, e := risk.NewCommandCounterPolicy(cfg)
	if e != nil {
		return fail()
	}
	original, e := prepareNativeCounter(policy, scope, subject, capabilityID, at)
	if e != nil {
		return fail()
	}
	expected, e := counterPlan(original.Bindings())
	if e != nil || expected != p {
		return fail()
	}
	return restoredCounter{command: original, policy: policy, current: b, scope: scope, subject: subject, capabilityID: capabilityID}, nil
}
