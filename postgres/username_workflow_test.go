package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestUsernameSigninUsesExistingPairedNativeCustody(t *testing.T) {
	s := passwordSigninCodecSpec(true)
	s.Operation.Owner, s.Operation.OperationID, s.Operation.SchemaID = "identity/username", "identity.username.signin", "username-signin"
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	command, _ := passwordSigninCodecCommand(t, s, []byte("synthetic-username-password"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)))
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil || claim.purpose != "identity.username.signin" || claim.feature == nil || *claim.feature != s.Operation {
		t.Fatal("native username signin lost original paired custody", err)
	}
	// Generic metadata must not stand in for the password and original cookie.
	plain, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareClaim(plain, [32]byte{1}); err == nil {
		t.Fatal("plain username metadata impersonated password custody")
	}
}

func TestUsernameOperationsReuseOnlyExactPasswordEngineContributor(t *testing.T) {
	for _, method := range []string{"signup", "signin"} {
		op := identity.FeatureOperation{Owner: "identity/username", OperationID: "identity.username." + method, SchemaID: "username-" + method, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
		d := ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
		phase := &featureRegistryContributor{descriptor: d, operations: []identity.FeatureOperation{op}}
		r, err := NewContributorRegistry([]Contributor{phase})
		if err != nil || len(r.FeatureOperations()) != 1 || r.FeatureOperations()[0].Operation != op {
			t.Fatal("username operation requires a duplicate password engine", err)
		}
		for _, mutate := range []func(*featureRegistryContributor){
			func(p *featureRegistryContributor) { p.operations[0].SchemaID = "password-" + method },
			func(p *featureRegistryContributor) { p.operations[0].SchemaVersion++ },
			func(p *featureRegistryContributor) { p.operations[0].OperationID = "identity.username.update" },
			func(p *featureRegistryContributor) { p.descriptor.ContractID = "unrelated" },
			func(p *featureRegistryContributor) { p.descriptor.Version++ },
		} {
			bad := &featureRegistryContributor{descriptor: d, operations: []identity.FeatureOperation{op}}
			mutate(bad)
			if _, err := NewContributorRegistry([]Contributor{bad}); err == nil {
				t.Fatal("closed username contributor ownership was widened")
			}
		}
	}
}

func TestUsernameSignupUsesOriginalNativeGenerationAndAcceptance(t *testing.T) {
	b, original, issued := signupPreparationPlanFixture(t)
	op := original.Feature.Operation
	op.Owner, op.OperationID, op.SchemaID = "identity/username", "identity.username.signup", "username-signup"
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32)))
	command, err := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, "$synthetic$username-verifier", cookie)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil || claim.purpose != op.OperationID {
		t.Fatal("native username signup lost original password custody", err)
	}
	for _, plan := range []CommandPlan{original, issued} {
		plan.Feature.Operation, plan.SignupAcceptance = op, true
		plan.Audits[0].RetentionClass = "protected"
		wire, err := encodeFeaturePlan(b, [32]byte{1}, plan)
		if err != nil {
			t.Fatal("username signup cannot retain original branches", err)
		}
		restored, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil || restored.Feature.Operation != op || !restored.SignupAcceptance {
			t.Fatal("restoration relabeled username signup", err)
		}
	}
}
