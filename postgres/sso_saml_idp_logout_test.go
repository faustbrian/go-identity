package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type samlIDPLogoutProbe struct{ scopeFeatureParticipant }

func (*samlIDPLogoutProbe) Descriptor() ContributorDescriptor { return SSOSAMLIDPLogoutDescriptor() }
func (*samlIDPLogoutProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

func samlIDPLogoutFixture(t *testing.T) (*samlIDPLogoutProbe, identity.FeatureCommandSpec, SSOSAMLIDPLogoutIntent) {
	t.Helper()
	op := SSOSAMLIDPLogoutOperation()
	owner := &samlIDPLogoutProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}
	b := codecBinding()
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(b.CommandID)
	b.ActorID, b.ActorKind, b.LinkMode = "saml-service", authorization.SubjectServiceAccount, 0
	intent := SSOSAMLIDPLogoutIntent{
		OrganizationID: "original-org", ProviderID: "original-provider", RequestDigest: [32]byte{42},
		ValidUntil: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Targets: []SSOSAMLIDPLogoutTarget{
			{SessionID: "session-a", FamilyID: "family-a", IssuanceCommandID: b.CommandID, Version: 3},
			{SessionID: "session-b", FamilyID: "family-b", IssuanceCommandID: b.CommandID, Version: 9},
		},
	}
	// The selected sessions have distinct authoritative issuance commands.
	for i := range intent.Targets {
		issuance, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		intent.Targets[i].IssuanceCommandID = issuance
	}
	fields, err := SSOSAMLIDPLogoutFields(intent)
	if err != nil {
		t.Fatal("valid signed request target set", err)
	}
	return owner, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, intent
}

func TestSSOSAMLIDPLogoutPlanIsServiceOnlyAndCredentialFree(t *testing.T) {
	for _, name := range []string{"signed service", "human actor", "foreign receipt", "session lifecycle", "unprotected audit", "missing commitment", "browser custody", "missing final fence"} {
		t.Run(name, func(t *testing.T) {
			c, _, p := coordinatorFixture(t)
			owner, spec, _ := samlIDPLogoutFixture(t)
			var participant FeatureExecutionContributor = owner
			if name == "missing final fence" {
				participant = &samlIDPLogoutNoFinal{owner.scopeFeatureParticipant}
			}
			registry, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, participant})
			if err != nil {
				t.Fatal("register exact owner", err)
			}
			c.registry = registry
			p.Contributors = registry.Descriptors()
			p.Feature = &FeatureRegistration{Contributor: participant.Descriptor(), Operation: spec.Operation}
			p.SubjectType = "sso_saml_logout"
			p.Lifecycle = &LifecyclePlan{EventType: "sso.saml_logout.revoked.v1", AfterVersion: 1}
			p.Audits[0].EventType, p.Audits[0].RetentionClass = spec.Operation.OperationID, "protected"
			actor := audit.ActorService
			switch name {
			case "human actor":
				spec.Binding.ActorKind, actor = authorization.SubjectUser, audit.ActorHuman
			case "foreign receipt":
				spec.Binding.RecordID = "another-request"
			case "session lifecycle":
				p.Lifecycle.EventType = "session.revoked.v1"
			case "unprotected audit":
				p.Audits[0].RetentionClass = "ordinary"
			case "missing commitment":
				spec.Fields = spec.Fields[:len(spec.Fields)-1]
			}
			p.Audits[0].BindingDigest = securityAuditScopeDigest(spec.Binding, &spec.Operation, p.SubjectType, spec.Binding.RecordID, actor, "identity-feature-audit-binding-v1")
			command, err := identity.NewFeatureCommand(spec)
			if name == "browser custody" {
				command, err = identity.NewFeaturePreAuthCommand(spec, authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
			}
			if err != nil {
				t.Fatal("construct structural command", err)
			}
			got, err := c.PrepareCommandPlan(spec.Binding, command, p)
			if (err == nil && got.Digest != ([32]byte{})) != (name == "signed service") {
				t.Fatal("unexpected IdP logout admission", err)
			}
		})
	}
}

type samlIDPLogoutNoFinal struct{ scopeFeatureParticipant }

func (*samlIDPLogoutNoFinal) Descriptor() ContributorDescriptor { return SSOSAMLIDPLogoutDescriptor() }

func TestSSOSAMLIDPLogoutWorkFencesWholeTargetSet(t *testing.T) {
	for _, name := range []string{"apply", "commit", "different invocation", "reconstructed command", "reconstructed final command", "retargeted session", "retargeted issuance", "retargeted provider", "retargeted organization", "changed request", "changed expiry", "changed version", "missing target", "too many targets", "unordered targets", "duplicate target", "browser operation", "preparation"} {
		t.Run(name, func(t *testing.T) {
			owner, spec, intent := samlIDPLogoutFixture(t)
			original, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			feature := &FeatureRegistration{Operation: spec.Operation, Contributor: owner.Descriptor()}
			lifecycle := LifecyclePlan{EventType: "sso.saml_logout.revoked.v1", AfterVersion: 1}
			frozen := &admittedKernelPlan{binding: spec.Binding, feature: feature, lifecycle: &lifecycle, fingerprint: [32]byte{7}}
			w := Work{state: &workState{ctx: t.Context(), binding: spec.Binding, generation: 3, feature: feature,
				subjectType: "sso_saml_logout", lifecycle: &workLifecycle{plan: lifecycle}, featureInvocation: owner,
				featureApplying: true, featureApplyCommand: &original, execution: &domainExecution{reservation: &reservationState{plan: frozen, journal: journalReservation{generation: 3}}}}}
			command := original
			if name == "commit" || name == "reconstructed final command" {
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &original
				w.state.featureReceipt = &identity.FeatureReceipt{}
			}
			switch name {
			case "different invocation":
				w.state.featureInvocation = &samlIDPLogoutProbe{}
			case "reconstructed command", "reconstructed final command":
				command, err = identity.NewFeatureCommand(spec)
				if err != nil {
					t.Fatal(err)
				}
			case "retargeted session":
				intent.Targets[1].SessionID = "session-c"
			case "retargeted issuance":
				intent.Targets[1].IssuanceCommandID = spec.Binding.CommandID
			case "retargeted provider":
				intent.ProviderID = "another-provider"
			case "retargeted organization":
				intent.OrganizationID = "another-org"
			case "changed request":
				intent.RequestDigest[0]++
			case "changed expiry":
				intent.ValidUntil = intent.ValidUntil.Add(time.Microsecond)
			case "changed version":
				intent.Targets[1].Version++
			case "missing target":
				intent.Targets = intent.Targets[:1]
			case "too many targets":
				intent.Targets = make([]SSOSAMLIDPLogoutTarget, 129)
			case "unordered targets":
				slices.Reverse(intent.Targets)
			case "duplicate target":
				intent.Targets[1] = intent.Targets[0]
			case "browser operation":
				feature.Operation = SSOSAMLLogoutStartOperation()
			case "preparation":
				w.state.featurePreparationPlan = frozen
			}
			err = w.RequireSSOSAMLIDPLogoutRequest(t.Context(), owner, command, intent)
			if name == "apply" || name == "commit" {
				if err != nil || w.usable() != nil {
					t.Fatal("original IdP logout scope denied", err)
				}
			} else if err == nil || w.usable() == nil {
				t.Fatal("altered IdP logout scope did not poison Work", err)
			}
		})
	}
}
