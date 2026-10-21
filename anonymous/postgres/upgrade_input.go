package anonymouspostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func upgradePreparationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: upgradeOperation().OperationID, SchemaID: "identity.anonymous.upgrade.prepare.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
}

// These private projections exist only in the existing authenticated encrypted
// request/preparation journals. Public opaque values intentionally reject JSON.
type upgradeStoredConflict anonymous.Conflict
type upgradeStoredCapability kernel.CapabilityPlan
type upgradeInput struct {
	Schema                  uint8
	Preparation             identity.CommandBinding
	Final                   identity.FeatureCommandSpec
	Guest                   []identity.FeatureField
	Subject                 signinStoredSubject
	Conflicts               []upgradeStoredConflict
	Kernel                  deletionStoredKernel
	Proof                   auth.ReauthenticationProof
	Intent                  []identity.FeatureField
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
	Started, Until          time.Time
	FactorVersion           uint64
}

type upgradePreparation struct {
	service               *UpgradeService
	request               anonymous.UpgradeRequest
	input                 upgradeInput
	merge                 anonymous.MergePlan
	guest, target, result session.Session
	primary               passwordpg.ActionPrimaryAdmission
	original, command     identity.Command
	final                 *upgradeExecution
	coordinator           *kernel.Coordinator
	registry              *kernel.ContributorRegistry
	issuer                *session.SessionIssuer
	prospective           session.PreparedIssuance
	issued                capabilitypg.PreparedIssuance
	issuance              kernel.CapabilityIssuancePlan
	output                upgradeOutput
	outputDigest          [32]byte
	generation            uint64
}

func (*upgradePreparation) Descriptor() kernel.ContributorDescriptor { return creationOwner() }
func (*upgradePreparation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{upgradePreparationOperation()}
}
func (p *upgradePreparation) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: upgradePreparationOperation()}
}

func (p *upgradePreparation) coordinatorFor(final bool) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	s := p.service
	var owners []kernel.Contributor
	if final {
		owners = []kernel.Contributor{s.guest.directory, s.guest.risk, a, l, p.final, capabilitypg.NewParticipant()}
	} else {
		owners = []kernel.Contributor{s.guest.directory, a, l, p, s.capability}
	}
	r, err := kernel.NewContributorRegistry(owners)
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.guest.pool, r, s.config().Guest.Coordinator, s.config().Guest.RequestKeys)
	return c, r, err
}

func (p *upgradePreparation) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	c := p.service.config().Guest
	if k.Feature != p.registration() || k.Scope.Method != "POST" || k.Scope.RouteID != upgradeOperation().OperationID || k.Scope.ActorKind != authorization.SubjectUser || k.Namespace != c.RequestKeys.Namespace || k.PolicyVersion != c.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, err
	}
	frame, err := json.Marshal(struct {
		Binding signinStoredKey
		Profile [32]byte
	}{signinStoredKey(k), p.service.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	sum := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-anonymous-upgrade-input-v1", "binding": base64.RawURLEncoding.EncodeToString(sum[:])})
}

func (p *upgradePreparation) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	s, r, c := p.service, p.request, p.service.config()
	aad, err := p.inputAAD(k)
	if err != nil || r.Validate() != nil {
		return nil, anonymous.ErrInvalidInput
	}
	// Start the single original evidence budget BEFORE any contributing owner
	// read. SQL/read/callback waits consume it; later phases cannot reset it.
	var started time.Time
	if err = s.guest.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started); err != nil {
		return nil, identity.UnavailableError{}
	}
	started = started.UTC()
	guest, err := s.guest.reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: r.Guest})
	if err != nil {
		return nil, err
	}
	if !guest.Recognized || guest.ValidateAt(c.Guest.Validation.Clock.Now()) != nil || !s.guest.possesses(r.TenantID, r.Guest, r.GuestCSRF, guest.Session) {
		return nil, identity.ForbiddenError{}
	}
	gs, _ := guest.Session.Bindings()
	plan, err := r.Plan.Validated()
	if err != nil || !supportedUpgradePlan(plan) {
		return nil, anonymous.ErrInvalidInput
	}
	subject, err := s.guest.repository.Read(ctx, anonymous.SubjectQuery{TenantID: r.TenantID, UserID: gs.UserID})
	if err != nil {
		return nil, err
	}
	expected, _ := plan.Source.Record()
	actual, _ := subject.Record()
	if expected != actual || actual.State != anonymous.StateActive || actual.Version == 0 || subject.RequireActive(r.TenantID, c.Guest.Validation.Clock.Now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	snapshot, err := s.guest.directory.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: r.TenantID, UserID: gs.UserID})
	if err != nil {
		return nil, err
	}
	finalID, err := identity.NewCommandID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	b := identity.CommandBinding{CommandID: finalID, TenantID: r.TenantID, UserID: identity.UserID(plan.Target), ActorID: identity.ActorID(plan.Target), ActorKind: authorization.SubjectUser, OperationID: upgradeOperation().OperationID, SchemaID: upgradeOperation().SchemaID, SchemaVersion: 1, PolicyID: c.Guest.PolicyID, PolicyVersion: k.PolicyVersion, CorrelationID: string(k.Admission.CommandID), RecordID: string(gs.UserID)}
	primary, err := s.primary.Prepare(ctx, passwordpg.ActionPrimaryRequest{TenantID: r.TenantID, CommandID: finalID, RecordID: b.RecordID, Session: r.TargetSession, Proof: r.TargetProof, Caller: r.Caller, CSRFToken: r.TargetCSRF})
	if err != nil {
		return nil, err
	}
	target, err := primary.Original()
	if err != nil || !s.targetPossession(r.TenantID, r.TargetSession, r.TargetCSRF, target) {
		return nil, identity.ForbiddenError{}
	}
	ts, _ := target.Bindings()
	if ts.UserID != b.UserID || ts.UserID == gs.UserID || ts.Remember != r.Remember || gs.Remember != r.Remember {
		return nil, identity.ForbiddenError{}
	}
	until := started.Add(20 * time.Second)
	deadline, err := primary.Deadline()
	if err != nil {
		return nil, err
	}
	for _, bound := range []time.Time{deadline, guest.ValidUntil(), actual.ExpiresAt} {
		if bound.Before(until) {
			until = bound
		}
	}
	// Capability's signed expiry is whole-second UTC. Freeze that earlier bound
	// now so commit, prospective session delivery and retries share the same
	// earliest deadline rather than keeping a fractional post-grant window.
	until = until.Truncate(time.Second)
	decision, err := c.Guest.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, s.guest.caller(r.TenantID, b.UserID, b.OperationID, "identity.anonymous", b.RecordID))
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(b.PolicyVersion) {
		return nil, identity.ForbiddenError{}
	}
	factors, err := mfapg.ReadAnonymousUpgradeFactors(ctx, s.guest.pool, b.TenantID, b.UserID, c.Guest.Repository.MaximumDuration)
	if err != nil {
		return nil, err
	}
	action, disposal := identity.RetentionDelete, kernel.AnonymousDisposeDelete
	if actual.Cleanup == anonymous.CleanupAnonymize {
		action, disposal = identity.RetentionAnonymize, kernel.AnonymousDisposeAnonymize
	}
	if actual.Cleanup == anonymous.CleanupRetain {
		disposal = kernel.AnonymousDisposeRetain
	}
	retention, err := c.Guest.Retention.DecideRetention(ctx, identity.RetentionPolicyInput{TenantID: b.TenantID, ActorID: b.ActorID, SubjectID: gs.UserID, OperationID: b.OperationID, PolicyVersion: c.Guest.RetentionPolicyVersion, Deadline: until, Resource: identity.RetentionResource{Kind: "anonymous", ID: b.RecordID}, Action: action, LegalHold: snapshot.LegalHold, RequestedAt: started})
	if err != nil || retention.Disposition != identity.RetentionAllow {
		return nil, identity.ForbiddenError{}
	}
	dispose := kernel.AnonymousDisposalIntent{Snapshot: snapshot, Action: disposal, RetentionPolicyVersion: c.Guest.RetentionPolicyVersion}
	fields, err := UpgradeFields(plan)
	if err != nil {
		return nil, err
	}
	owned, err := kernel.AnonymousDisposalFields(dispose)
	if err != nil {
		return nil, err
	}
	fields = append(fields, owned...)
	originalIntent, ok := intent.Fields()
	if !ok {
		return nil, anonymous.ErrInvalidInput
	}
	for _, f := range originalIntent {
		f.Name = "anonymous.request." + f.Name
		fields = append(fields, f)
	}
	fields = append(fields, identity.FeatureField{Name: "anonymous.source-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: actual.Version}}, identity.FeatureField{Name: "anonymous.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: until}}, identity.FeatureField{Name: "mfa.anonymous-upgrade.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factors.Version()}})
	command, err := primary.Command(b, fields)
	if err != nil {
		return nil, err
	}
	f, _ := command.Feature()
	guestFields, err := sessionpg.AnonymousSourceSessionFields(guest.Session)
	if err != nil {
		return nil, err
	}
	preparation := b
	preparation.CommandID, preparation.RecordID, preparation.SchemaID = k.Admission.CommandID, "", upgradePreparationOperation().SchemaID
	conflicts := make([]upgradeStoredConflict, len(plan.Conflicts))
	for i, decision := range plan.Conflicts {
		conflicts[i] = upgradeStoredConflict(decision)
	}
	input := upgradeInput{Schema: 1, Preparation: preparation, Final: f, Guest: guestFields, Subject: signinStoredSubject(actual), Conflicts: conflicts, Kernel: storeDeletionKernel(dispose), Proof: r.TargetProof, Intent: originalIntent, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device, Started: started, Until: until, FactorVersion: factors.Version()}
	if !c.Guest.Validation.Clock.Now().Before(until) {
		return nil, identity.ForbiddenError{}
	}
	return sealAnonymousInput(ctx, s.guest.crypto, c.Guest.ActiveEnvelopeKeyID, aad, input)
}

func (p *upgradePreparation) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, intent identity.RequestIntent) error {
	aad, err := p.inputAAD(k)
	if err != nil {
		return err
	}
	var input upgradeInput
	if err = openAnonymousInput(ctx, p.service.guest.crypto, aad, wire, &input); err != nil {
		return err
	}
	b, prep := input.Final.Binding, input.Preparation
	if input.Schema != 1 || prep.ValidateFor(upgradePreparationOperation()) != nil || b.ValidateFor(upgradeOperation()) != nil || prep.CommandID != k.Admission.CommandID || prep.CommandID == b.CommandID || b.TenantID != k.Scope.TenantID || prep.TenantID != b.TenantID || b.ActorID != k.Scope.ActorID || prep.UserID != b.UserID || prep.ActorID != b.ActorID || prep.PolicyID != b.PolicyID || prep.PolicyVersion != b.PolicyVersion || b.PolicyID != p.service.config().Guest.PolicyID || b.PolicyVersion != k.PolicyVersion || input.Final.Operation != upgradeOperation() || !readInstant(input.Started) || !readInstant(input.Until) || !input.Until.After(input.Started) || input.Until.After(input.Started.Add(20*time.Second)) || input.FactorVersion == 0 {
		return anonymous.ErrInvalidInput
	}
	if fields, ok := intent.Fields(); ok && !reflect.DeepEqual(fields, input.Intent) {
		return identity.ConflictError{}
	}
	if p.request.Origin != input.Origin || p.request.Network != input.Network || p.request.Device != input.Device {
		return identity.ForbiddenError{}
	}
	subject, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec(input.Subject))
	if err != nil {
		return err
	}
	conflicts := make([]anonymous.Conflict, len(input.Conflicts))
	for i, decision := range input.Conflicts {
		conflicts[i] = anonymous.Conflict(decision)
	}
	merge, err := (anonymous.MergePlan{Source: subject, Target: identity.SubjectID(b.UserID), Conflicts: conflicts}).Validated()
	if err != nil || !supportedUpgradePlan(merge) {
		return anonymous.ErrInvalidInput
	}
	guest, err := sessionpg.AnonymousSourceSessionFromFields(b.TenantID, identity.UserID(b.RecordID), input.Guest)
	if err != nil || !p.service.guest.possesses(b.TenantID, p.request.Guest, p.request.GuestCSRF, guest) {
		return identity.ForbiddenError{}
	}
	primary, err := p.service.primary.Restore(ctx, passwordpg.ActionPrimaryRequest{TenantID: b.TenantID, CommandID: b.CommandID, RecordID: b.RecordID, Session: p.request.TargetSession, Proof: input.Proof, Caller: input.Caller, CSRFToken: p.request.TargetCSRF}, input.Final.Fields)
	if err != nil {
		return err
	}
	target, err := primary.Original()
	if err != nil || !p.service.targetPossession(b.TenantID, p.request.TargetSession, p.request.TargetCSRF, target) {
		return identity.ForbiddenError{}
	}
	command, err := identity.NewFeatureSessionCommand(input.Final, p.request.TargetSession)
	if err != nil || ValidateUpgradePlan(command, merge) != nil {
		return anonymous.ErrInvalidInput
	}
	if _, err = kernel.AnonymousDisposalFields(input.Kernel.intent()); err != nil {
		return err
	}
	original, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: prep, Operation: upgradePreparationOperation(), Fields: slices.Clone(input.Final.Fields)})
	if err != nil {
		return err
	}
	p.input, p.merge, p.guest, p.target, p.primary, p.original = input, merge, guest, target, primary, original
	p.issuer, err = session.NewAnonymousUpgradeSessionIssuerWithCSRF(p.final, p.service.config().Issuer, p.service.config().CSRF)
	return err
}
