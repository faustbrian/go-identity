package postgres

import (
	"context"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type mfaSendCounterSourceProbe struct {
	scopeFeatureParticipant
	user           identity.UserID
	denied, panics bool
}

// A zero-size pointer is not a distinct Go principal: separate allocations may
// compare equal. Real counter repositories have state; retain that distinction.
type mfaSendCounterOwnerProbe struct {
	commandCounterProbe
	marker byte
}

func (*mfaSendCounterSourceProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*mfaSendCounterSourceProbe) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	return nil
}
func (p *mfaSendCounterSourceProbe) MFALoginSendCounterSubject(identity.Command) (identity.UserID, error) {
	if p.panics {
		panic("private source detail")
	}
	if p.denied {
		return "", identity.ForbiddenError{}
	}
	return p.user, nil
}

func TestMFALoginSendCounterScopeRequiresRegisteredNativeSource(t *testing.T) {
	_, base, _ := featurePlanFixture(t)
	s, _ := base.Feature()
	s.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.UserID, s.Binding.AnonymousFlowID, s.Binding.RecordID = "", "bbbbbbbbbbbbbbbbbbbbbg", "AQEBAQEBAQEBAQEBAQEBAQ"
	command, err := identity.NewFeaturePreAuthCommand(s, auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	source := &mfaSendCounterSourceProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}, user: "verified-original"}
	counter := &mfaSendCounterOwnerProbe{marker: 1}
	registry, err := NewContributorRegistry([]Contributor{source, counter})
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{registry: registry}
	plan := &admittedKernelPlan{registry: registry.state, binding: s.Binding, feature: &FeatureRegistration{Contributor: source.Descriptor(), Operation: s.Operation}, counters: &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{1}}}
	w := Work{state: &workState{ctx: context.Background(), registry: registry.state, binding: s.Binding, feature: plan.feature, execution: &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: plan, journal: journalReservation{generation: 1}}}}}
	state := &commandCounterState{work: w, participant: counter, command: command, active: true}
	for _, handle := range []interface {
		MFALoginSendScope(CommandCounterContributor) (identity.UserID, string, error)
	}{CommandCounterWork{state: state}, CommandCounterAdmissionWork{state: state}} {
		user, browser, err := handle.MFALoginSendScope(counter)
		if err != nil || user != source.user || browser != s.Binding.AnonymousFlowID {
			t.Fatal("native original counter scope unavailable", err)
		}
		if _, _, err := handle.MFALoginSendScope(&mfaSendCounterOwnerProbe{marker: 1}); err == nil {
			t.Fatal("descriptor alias obtained native source")
		}
	}
	for _, mode := range []string{"returned", "closed", "denied", "panic", "empty-subject", "other-profile", "different-command", "without-cookie", "foreign-registry"} {
		t.Run(mode, func(t *testing.T) {
			copyState := *state
			copyWork := *w.state
			copyPlan := *plan
			copyFeature := *plan.feature
			copyPlan.feature = &copyFeature
			copyReservation := reservationState{coordinator: c, plan: &copyPlan, journal: journalReservation{generation: 1}}
			copyExecution := *w.state.execution
			copyExecution.reservation = &copyReservation
			copyWork.execution = &copyExecution
			copyState.work = Work{state: &copyWork}
			source.denied, source.panics = false, false
			source.user = "verified-original"
			switch mode {
			case "returned":
				copyState.active = false
			case "closed":
				copyWork.closed = true
			case "denied":
				source.denied = true
			case "panic":
				source.panics = true
			case "empty-subject":
				source.user = ""
			case "other-profile":
				copyFeature.Operation.SubjectRequirement = identity.FeatureSubjectUser
			case "different-command":
				copyPlan.binding.CommandID, _ = identity.NewCommandID()
			case "without-cookie":
				copyState.command, _ = identity.NewFeatureCommand(s)
			case "foreign-registry":
				copyWork.registry = nil
			}
			if user, browser, err := (CommandCounterWork{state: &copyState}).MFALoginSendScope(counter); err == nil || user != "" || browser != "" {
				t.Fatal("invalid source disclosed a counter subject")
			}
		})
	}
}
