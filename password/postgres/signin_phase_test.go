package passwordpostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	"time"
)

func TestNativeSigninPhaseCannotExecuteWithoutOriginalCustody(t *testing.T) {
	p := &signinPhase{}
	if p.ValidateFeatureCommand(identity.Command{}, kernel.CommandPlan{}) == nil {
		t.Fatal("missing original comparison admitted")
	}
	if _, err := p.ApplyFeature(context.Background(), kernel.Work{}, identity.Command{}); err == nil {
		t.Fatal("zero Work admitted")
	}
	if status, err := p.RecoverParticipant(context.Background(), kernel.RecoveryWork{}); err == nil || status != kernel.RecoveryUnknown {
		t.Fatal("missing recovery authority claimed rollback")
	}
	var absent *signinPhase
	if absent.matches(identity.Command{}) {
		t.Fatal("absent phase matched")
	}
}

func TestNativeSigninPhaseRetainsExactPasswordOwner(t *testing.T) {
	r, flow, key, _ := nativeSigninFlow(t)
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
	f := identity.FeatureCommandSpec{Operation: op, Binding: identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: "ingress", ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, PolicyID: "login", PolicyVersion: 3, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "signin-attempt"}}
	command, err := identity.NewFeaturePasswordSigninCommand(f, r.Password, r.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := sessionpg.NewPasswordSigninEffect(sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"})
	if err != nil {
		t.Fatal(err)
	}
	p := &signinPhase{operation: op, expected: command, request: r, effect: effect, flow: flow, flowKey: key}
	if !p.matches(command) {
		t.Fatal("original immutable command denied")
	}
	copy := command
	if !p.matches(copy) {
		t.Fatal("original value copy denied")
	}
	replacement, err := primitive.NewSecret([]byte("different synthetic password"))
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Destroy()
	changed, err := identity.NewFeaturePasswordSigninCommand(f, replacement, r.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if p.matches(changed) {
		t.Fatal("replacement password owner admitted")
	}
	r.Password.Destroy()
	if p.matches(copy) {
		t.Fatal("destroyed original password admitted")
	}
}
