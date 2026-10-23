package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type oauthConsentProbe struct{ scopeFeatureParticipant }

func (*oauthConsentProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
}
func (*oauthConsentProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}
func (*oauthConsentProbe) ValidateOAuthConsent(identity.Command) error { return nil }

type oauthConsentOutboxProbe struct{ riskPassiveProbe }

func (*oauthConsentOutboxProbe) PersistOAuthConsent(context.Context, Work) error { return nil }

func oauthConsentPlanFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan, *oauthConsentProbe, *oauthConsentOutboxProbe) {
	t.Helper()
	c, _, p := featurePlanFixture(t)
	b := codecBinding()
	b.OperationID = "identity.oauth-server.continue"
	b.SchemaID = b.OperationID + ".public-password-v1"
	b.RecordID = "grant-a"
	b.ActorID = identity.ActorID(b.UserID)
	op := identity.FeatureOperation{Owner: "oauth-server", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	owner := &oauthConsentProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}
	p.Feature = &FeatureRegistration{Operation: op, Contributor: owner.Descriptor()}
	p.SubjectType = "oauth_grant"
	p.Lifecycle = &LifecyclePlan{EventType: "grant.authorized.v1", BeforeVersion: 1, AfterVersion: 2}
	p.Audits[0].EventType = "identity.oauth_server.grant_consent"
	p.Audits[0].RetentionClass = "protected"
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{5}}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{
		{Name: "oauth.consent-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(b.CommandID)}},
		{Name: "oauth.consent-before-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 0}},
		{Name: "oauth.consent-after-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
		{Name: "oauth.consent-created", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}},
	}})
	auditor := &riskPassiveProbe{registryContributor{p.Contributors[1]}}
	outbox := &oauthConsentOutboxProbe{riskPassiveProbe{registryContributor{p.Contributors[2]}}}
	entries := []Contributor{&Repository{}, auditor, outbox, owner, &magicLinkPreparationCounter{}}
	var err error
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	p.Contributors = c.registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	return c, command, p, owner, outbox
}

func TestOAuthConsentAdmissionRequiresAtomicSecondaryOwner(t *testing.T) {
	c, command, p, owner, outbox := oauthConsentPlanFixture(t)
	s, _ := command.Feature()
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err != nil {
		t.Fatal("complete consent owner denied", err)
	}
	c.registry, _ = NewContributorRegistry([]Contributor{&Repository{}, c.registry.state.entries[1].contributor, &outbox.riskPassiveProbe, owner, &magicLinkPreparationCounter{}})
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err == nil {
		t.Fatal("consent admitted with ordinary single-event outbox")
	}
}

func oauthConsentInvocationFixture(t *testing.T, before uint64) (Work, *oauthConsentProbe, OAuthConsentMutation) {
	t.Helper()
	_, command, p, owner, _ := oauthConsentPlanFixture(t)
	s, _ := command.Feature()
	mutation := OAuthConsentMutation{ID: string(s.Binding.CommandID), BeforeVersion: before, AfterVersion: before + 1, Created: before == 0}
	for n := range s.Fields {
		switch s.Fields[n].Name {
		case "oauth.consent-before-version":
			s.Fields[n].Value.Uint64 = mutation.BeforeVersion
		case "oauth.consent-after-version":
			s.Fields[n].Value.Uint64 = mutation.AfterVersion
		case "oauth.consent-created":
			s.Fields[n].Value.Bool = mutation.Created
		}
	}
	command = featureCodecCommand(t, s)
	plan := &admittedKernelPlan{binding: s.Binding, feature: p.Feature, lifecycle: p.Lifecycle, counters: p.CommandCounters, fingerprint: [32]byte{7}, subjectType: p.SubjectType, audits: p.Audits}
	r := &reservationState{plan: plan, journal: journalReservation{generation: 1}}
	w := Work{state: &workState{ctx: context.Background(), binding: s.Binding, generation: 1, feature: p.Feature, subjectType: p.SubjectType, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, execution: &domainExecution{reservation: r}}}
	return w, owner, mutation
}

func TestOAuthConsentReceiptCannotSubstituteOwnerIDOrVersion(t *testing.T) {
	for _, mode := range []string{"foreign owner", "wrong id", "grant as consent", "version", "created flag", "returned", "commit phase", "missing command", "missing field"} {
		t.Run(mode, func(t *testing.T) {
			w, owner, mutation := oauthConsentInvocationFixture(t, 2)
			switch mode {
			case "foreign owner":
				owner = &oauthConsentProbe{}
			case "wrong id":
				mutation.ID = "AQEBAQEBAQEBAQEBAQEBAQ"
			case "grant as consent":
				mutation.ID = w.state.binding.RecordID
			case "version":
				mutation.BeforeVersion++
				mutation.AfterVersion++
			case "created flag":
				mutation.Created = true
			case "returned":
				w.state.featureInvocation = nil
			case "commit phase":
				w.state.featureApplying = false
			case "missing command":
				w.state.featureApplyCommand = nil
			case "missing field":
				s, _ := w.state.featureApplyCommand.Feature()
				s.Fields = s.Fields[:len(s.Fields)-1]
				command := featureCodecCommand(t, s)
				w.state.featureApplyCommand = &command
			}
			if err := w.RecordOAuthConsent(owner, mutation); err == nil || w.usable() == nil {
				t.Fatal("invalid receipt left usable transaction")
			}
		})
	}
	if err := (Work{}).RecordOAuthConsent(&oauthConsentProbe{}, OAuthConsentMutation{}); err == nil {
		t.Fatal("zero Work acquired consent authority")
	}
}

func TestOAuthConsentLifecycleUsesIndependentActualMutation(t *testing.T) {
	for name, fixture := range map[string]func(*testing.T, uint64) (Work, *oauthConsentProbe, OAuthConsentMutation){
		"password": oauthConsentInvocationFixture,
		"device":   deviceConsentInvocation,
	} {
		t.Run(name, func(t *testing.T) {
			for _, before := range []uint64{0, 2} {
				w, owner, mutation := fixture(t, before)
				if err := w.RecordOAuthConsent(owner, mutation); err != nil {
					t.Fatal("exact native consent receipt denied", err)
				}
				if _, err := w.StagedOAuthConsent(); err == nil {
					t.Fatal("missing primary audit yielded secondary success")
				}
				p := w.state.execution.reservation.plan
				now := time.Now().UTC().Truncate(time.Microsecond)
				record, err := securityMutationAudit(t.Context(), w.state.binding, 1, 2, now, "committed", p.audits[0].EventType, p.subjectType, w.state.binding.RecordID, "protected", true)
				if err != nil {
					t.Fatal(err)
				}
				p.audits[0].BindingDigest, err = FeatureAuditBindingDigest(w.state.binding, p.feature.Operation, p.subjectType, record)
				if err != nil {
					t.Fatal(err)
				}
				if err = bindAuditPlans(w, p.audits); err != nil {
					t.Fatal(err)
				}
				if err = w.StageAudit(0, record); err != nil {
					t.Fatal(err)
				}
				if err = w.StageLifecycle(0, now); err != nil {
					t.Fatal(err)
				}
				w.state.featureReceipt = &identity.FeatureReceipt{Operation: p.feature.Operation, BeforeVersion: 1, AfterVersion: 2}
				got, err := w.StagedOAuthConsent()
				event := "consent.reconfirmed.v1"
				if before == 0 {
					event = "consent.created.v1"
				}
				if err != nil || got.SubjectType != "oauth_consent" || got.SubjectID != mutation.ID || got.SubjectID == w.state.binding.RecordID || got.BeforeVersion != before || got.AfterVersion != before+1 || got.EventType != event || got.EventIndex != 1 || got.OccurredAt != now {
					t.Fatal("secondary consent substituted grant/versions", got, err)
				}
				primary, _ := w.StagedLifecycle()
				if got.ID == primary[0].ID {
					t.Fatal("consent event collides with grant event")
				}
				if err = w.RecordOAuthConsent(owner, mutation); err == nil || w.usable() == nil {
					t.Fatal("repeated mutation receipt not terminally denied")
				}
			}
		})
	}
}
