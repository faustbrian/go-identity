package postgres

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestSignupAcceptanceDeclarationPreservesBothBranches(t *testing.T) {
	b, original, issued := signupPreparationPlanFixture(t)
	original.Audits[0].RetentionClass = "protected"
	issued.Audits[0].RetentionClass = "protected"
	for _, plan := range []CommandPlan{original, issued} {
		legacy, err := encodeFeaturePlan(b, [32]byte{1}, plan)
		if err != nil {
			t.Fatal(err)
		}
		plan.SignupAcceptance = true
		wire, err := encodeFeaturePlan(b, [32]byte{1}, plan)
		if err != nil || bytes.Equal(wire, legacy) {
			t.Fatal("neutral branch absent from original intent", err)
		}
		got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		plan.Digest = sha256.Sum256(wire)
		if err != nil || !reflect.DeepEqual(got, plan) {
			t.Fatal("frozen signup branches changed", err)
		}
		plan.SignupAcceptance = false
		unchanged, err := encodeFeaturePlan(b, [32]byte{1}, plan)
		if err != nil || !bytes.Equal(legacy, unchanged) {
			t.Fatal("historical creation bytes changed", err)
		}
		if _, err := decodeKernelPlan(b, [32]byte{1}, wire); err == nil {
			t.Fatal("anonymous signup became kernel creation authority")
		}
		for i := range wire {
			if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
				t.Fatal("truncated alternate branch admitted")
			}
		}
		for _, bad := range [][]byte{
			append(bytes.Clone(wire), 0),
			cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText(signupAcceptanceProfile)}),
			bytes.Replace(wire, cborText(signupAcceptanceProfile), cborText("unknown-profile"), 1),
		} {
			if _, err := decodeFeaturePlan(b, [32]byte{1}, bad); err == nil {
				t.Fatal("malformed alternate branch admitted")
			}
		}
	}
	original.SignupAcceptance, issued.SignupAcceptance = true, true
	if !preparationFinalDeclaration(b, original, issued) {
		t.Fatal("prepared signup lost declared acceptance branch")
	}
	issued.SignupAcceptance = false
	if preparationFinalDeclaration(b, original, issued) || preparationFinalDeclaration(b, issued, original) {
		t.Fatal("restoration changed original branch declaration")
	}
}

func TestSignupAcceptanceDeclarationIsClosed(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"authenticated": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "user"; b.AnonymousFlowID = "" },
		"missing-flow":  func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "" },
		"other-operation": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.OperationID = "identity.password.signin"
		},
		"legacy-subject": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.SubjectRequirement = identity.FeatureSubjectUser
		},
		"missing-feature":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature = nil },
		"missing-audit":       func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits = nil },
		"unprotected-audit":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"foreign-contributor": func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.ContractID = "another" },
		"missing-lifecycle":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle = nil },
		"changed-lifecycle":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = signupAcceptedEvent },
		"wrong-subject":       func(_ *identity.CommandBinding, p *CommandPlan) { p.SubjectType = "session" },
		"changed-versions":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.AfterVersion = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			b, p, _ := signupPreparationPlanFixture(t)
			p.SignupAcceptance = true
			p.Audits[0].RetentionClass = "protected"
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err != nil {
				t.Fatal("closed-case positive control invalid", err)
			}
			change(&b, &p)
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign neutral branch declared")
			}
		})
	}
	if user, accepted, err := (*PasswordRegistrationDomain)(nil).ApplyOrAccept(nil, Work{}, nil, identity.Command{}, PasswordRegistrationIntent{}); err == nil || accepted || user != (identity.User{}) {
		t.Fatal("zero domain accepted signup")
	}
}

func FuzzSignupAcceptancePlan(f *testing.F) {
	f.Add([]byte{0xa2})
	f.Add(cborMap(map[string][]byte{"base": cborBytes([]byte{0xa2}), "profile": cborText(signupAcceptanceProfile)}))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65537 {
			t.Skip()
		}
		b := codecBinding()
		_, _ = decodeSignupAcceptancePlan(b, [32]byte{1}, wire)
	})
}
