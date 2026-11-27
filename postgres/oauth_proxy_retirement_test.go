package postgres

import (
	"context"
	"encoding/base64"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type proxyRetirementScopeOwner struct{ scopeFeatureParticipant }

func (*proxyRetirementScopeOwner) Descriptor() ContributorDescriptor {
	return OAuthProxyOriginRetirementDescriptor()
}

func TestOAuthProxyOriginRetirementRejectsAuthenticationAndOtherEffects(t *testing.T) {
	b := proxyRetirementBinding()
	op, owner := OAuthProxyOriginRetirementOperation(), OAuthProxyOriginRetirementDescriptor()
	_, _, plan := featurePlanFixture(t)
	plan.Feature = &FeatureRegistration{Operation: op, Contributor: owner}
	plan.Contributors[len(plan.Contributors)-1] = owner
	plan.SubjectType = "oauth_proxy_retirement"
	lifecycle := OAuthProxyOriginRetirementLifecycle()
	plan.Lifecycle = &lifecycle
	plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "identity.oauth.proxy_custody.retire", "protected"
	fingerprint := [32]byte{1}
	if _, err := encodeFeaturePlan(b, fingerprint, plan); err != nil {
		t.Fatal("the narrow declaration must be encodable", err)
	}
	for name, broaden := range map[string]func(*CommandPlan){
		"new issuance":      func(p *CommandPlan) { p.CapabilityIssuance = &CapabilityIssuancePlan{} },
		"state consumption": func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"delivery":          func(p *CommandPlan) { p.Delivery = &DeliveryPlan{} },
		"another lifecycle": func(p *CommandPlan) { p.Lifecycle = &LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := plan
			broaden(&candidate)
			if _, err := encodeFeaturePlan(b, fingerprint, candidate); err == nil {
				t.Fatal("unrelated effect entered the retirement declaration")
			}
		})
	}
	c, err := NewOAuthProxyOriginRetirementCommand(b, OAuthProxyRetireProduction, identity.CommandID("BAQEBAQEBAQEBAQEBAQEBA"), 7)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := c.Feature()
	syntheticCredential := [32]byte{1}
	confused, err := identity.NewFeaturePreAuthCommand(spec, authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(syntheticCredential[:])))
	if err != nil {
		t.Fatal("the generic constructor is needed to exercise the retirement selector", err)
	}
	w, participant, _ := proxyRetirementWork(t, OAuthProxyRetireProduction)
	w.state.featureApplyCommand = &confused
	if scope, err := w.OAuthProxyOriginRetirementScope(t.Context(), participant, confused); scope != (OAuthProxyOriginRetirementScope{}) || err == nil {
		t.Fatal("credential-bearing command acquired retirement scope")
	}
}

func proxyRetirementBinding() identity.CommandBinding {
	b := codecBinding()
	op := OAuthProxyOriginRetirementOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.CommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
	b.UserID, b.ActorID, b.ActorKind = "", "proxy-retirement-service", authorization.SubjectServiceAccount
	b.AnonymousFlowID = "AgICAgICAgICAgICAgICAg"
	b.RecordID = b.AnonymousFlowID
	b.CorrelationID = "AwMDAwMDAwMDAwMDAwMDAw"
	return b
}

func proxyRetirementWork(t *testing.T, kind OAuthProxyRetirementKind) (Work, *proxyRetirementScopeOwner, identity.Command) {
	t.Helper()
	b := proxyRetirementBinding()
	command, err := NewOAuthProxyOriginRetirementCommand(b, kind, identity.CommandID("BAQEBAQEBAQEBAQEBAQEBA"), 7)
	if err != nil {
		t.Fatal("construct the exact original proxy-custody retirement", err)
	}
	_, _, template := featurePlanFixture(t)
	audits := append([]AuditPlan(nil), template.Audits...)
	audits[0].EventType, audits[0].RetentionClass, audits[0].Required = "identity.oauth.proxy_custody.retire", "protected", true
	owner := &proxyRetirementScopeOwner{scopeFeatureParticipant{operations: []identity.FeatureOperation{OAuthProxyOriginRetirementOperation()}}}
	feature := &FeatureRegistration{Contributor: owner.Descriptor(), Operation: OAuthProxyOriginRetirementOperation()}
	lifecycle := OAuthProxyOriginRetirementLifecycle()
	frozen := &admittedKernelPlan{
		binding: b, fingerprint: [32]byte{7}, feature: feature, lifecycle: &lifecycle,
		subjectType: "oauth_proxy_retirement", audits: audits,
	}
	reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
	w := Work{state: &workState{
		ctx: t.Context(), binding: b, generation: 3, feature: feature, lifecycle: &workLifecycle{plan: lifecycle},
		featureInvocation: owner, featureApplying: true, featureApplyCommand: &command,
		execution: &domainExecution{reservation: reservation},
	}}
	return w, owner, command
}

func TestOAuthProxyOriginRetirementScopeKeepsExactOriginalPurpose(t *testing.T) {
	for _, test := range []struct {
		name    string
		kind    OAuthProxyRetirementKind
		purpose string
	}{
		{"production", OAuthProxyRetireProduction, "identity.oauth.proxy-forward"},
		{"preview", OAuthProxyRetirePreview, "identity.oauth.callback"},
	} {
		t.Run(test.name, func(t *testing.T) {
			w, owner, command := proxyRetirementWork(t, test.kind)
			scope, err := w.OAuthProxyOriginRetirementScope(t.Context(), owner, command)
			binding := proxyRetirementBinding()
			if err != nil || scope.TenantID != binding.TenantID || scope.OriginCommandID != identity.CommandID(binding.CorrelationID) ||
				scope.FlowID != identity.PreAuthTransactionID(binding.AnonymousFlowID) || scope.GrantPurpose != test.purpose ||
				scope.SourceCommandID != identity.CommandID("BAQEBAQEBAQEBAQEBAQEBA") || scope.SourceVersion != 7 {
				t.Fatal("retirement changed the original tenant, origin, flow, grant purpose or exact source", err)
			}
			if w.state.sqlStarted || w.state.failed != nil {
				t.Fatal("scope extraction reached SQL or poisoned the valid original invocation")
			}
		})
	}
}

func TestOAuthProxyOriginRetirementScopeRejectsUnownedOrAlteredApply(t *testing.T) {
	for _, mode := range []string{
		"zero-work", "nil-context", "cancelled-context", "foreign-owner", "reconstructed-command", "missing-original",
		"admission-only", "final-commit", "returned", "closed", "wrong-descriptor", "wrong-operation", "wrong-lifecycle",
		"wrong-subject", "wrong-audit", "optional-audit", "unprotected-audit", "missing-audit",
	} {
		t.Run(mode, func(t *testing.T) {
			w, owner, command := proxyRetirementWork(t, OAuthProxyRetireProduction)
			candidate, participant, ctx := command, FeatureExecutionContributor(owner), context.Context(t.Context())
			switch mode {
			case "zero-work":
				w = Work{}
			case "nil-context":
				ctx = nil
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "foreign-owner":
				participant = &proxyRetirementScopeOwner{owner.scopeFeatureParticipant}
			case "reconstructed-command":
				var err error
				candidate, err = NewOAuthProxyOriginRetirementCommand(proxyRetirementBinding(), OAuthProxyRetireProduction, identity.CommandID("BAQEBAQEBAQEBAQEBAQEBA"), 7)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-original":
				w.state.featureApplyCommand = nil
			case "admission-only":
				w.state.featureApplying = false
			case "final-commit":
				w.state.featureApplying, w.state.featureApplyCommand, w.state.featureCommitCommand = false, nil, &command
			case "returned":
				w.state.featureInvocation = nil
			case "closed":
				w.state.closed = true
			case "wrong-descriptor":
				w.state.feature.Contributor.ContractID = "identity.oauth.other"
			case "wrong-operation":
				w.state.feature.Operation.SchemaID = "identity.oauth.other.native-v1"
			case "wrong-lifecycle":
				w.state.execution.reservation.plan.lifecycle.EventType = "session.created.v1"
				w.state.lifecycle.plan.EventType = "session.created.v1"
			case "wrong-subject":
				w.state.execution.reservation.plan.subjectType = "oauth_proxy_transaction"
			case "wrong-audit":
				w.state.execution.reservation.plan.audits[0].EventType = "identity.oauth.use_proxy"
			case "optional-audit":
				w.state.execution.reservation.plan.audits[0].Required = false
			case "unprotected-audit":
				w.state.execution.reservation.plan.audits[0].RetentionClass = "ordinary"
			case "missing-audit":
				w.state.execution.reservation.plan.audits = nil
			}
			scope, err := w.OAuthProxyOriginRetirementScope(ctx, participant, candidate)
			if err == nil || scope != (OAuthProxyOriginRetirementScope{}) {
				t.Fatal("unowned or broadened invocation acquired original retirement scope")
			}
			if w.state != nil && (w.state.sqlStarted || !w.state.closed && w.state.failed == nil) {
				t.Fatal("rejected retirement scope reached SQL or left the original Work usable")
			}
		})
	}
}

func TestOAuthProxyOriginRetirementCommandRejectsMalformedOriginals(t *testing.T) {
	for _, mode := range []string{
		"zero-kind", "unknown-kind", "zero-source", "malformed-source", "zero-version", "self-origin", "flow-origin", "malformed-origin",
		"malformed-flow", "foreign-record", "human-actor", "local-user",
	} {
		t.Run(mode, func(t *testing.T) {
			binding := proxyRetirementBinding()
			kind, source, version := OAuthProxyRetireProduction, identity.CommandID("BAQEBAQEBAQEBAQEBAQEBA"), uint64(7)
			switch mode {
			case "zero-kind":
				kind = OAuthProxyRetirementKind(0)
			case "unknown-kind":
				kind = OAuthProxyRetirementKind(255)
			case "zero-source":
				source = ""
			case "malformed-source":
				source = "not-a-command"
			case "zero-version":
				version = 0
			case "self-origin":
				binding.CorrelationID = string(binding.CommandID)
			case "flow-origin":
				binding.CorrelationID = binding.AnonymousFlowID
			case "malformed-origin":
				binding.CorrelationID = "not-a-command"
			case "malformed-flow":
				binding.AnonymousFlowID, binding.RecordID = "not-a-flow", "not-a-flow"
			case "foreign-record":
				binding.RecordID = "BQUFBQUFBQUFBQUFBQUFBQ"
			case "human-actor":
				binding.ActorKind = authorization.SubjectUser
			case "local-user":
				binding.UserID = "local-user"
			}
			if command, err := NewOAuthProxyOriginRetirementCommand(binding, kind, source, version); err == nil || command != (identity.Command{}) {
				t.Fatal("malformed or substituted original retirement command was accepted")
			}
		})
	}
}
