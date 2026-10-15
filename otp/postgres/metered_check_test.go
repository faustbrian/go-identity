package postgres

import (
	"context"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func meteredCheckCommand(t *testing.T, p *Contributor, original identity.Command, plan kernel.OTPAttemptPlan, submitted string, version uint64) (identity.Command, kernel.OTPAttemptPlan) {
	t.Helper()
	a, err := p.codec.restoreAttempt(original, plan)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := a.Bindings()
	spec, _ := original.Feature()
	owner, err := p.codec.restoreAuthority(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Operation.Owner, spec.Operation.OperationID, spec.Operation.SchemaID = "identity/otp", "identity.otp.check", "identity-otp-check"
	if spec.Operation.SubjectRequirement == identity.FeatureSubjectAnonymousFlow {
		spec.Operation.SchemaID = "identity-otp-check-preauth"
	}
	spec.Operation.RecordRequirement = identity.FeatureRecordOmitted
	spec.Binding.RecordID = ""
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	spec.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields = nil
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, err := auth.NewOneTimeCode(submitted)
	if err != nil {
		t.Fatal(err)
	}
	a, err = issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, b.Continuation, otp.AttemptModeCheck, version, code)
	if err != nil {
		t.Fatal(err)
	}
	var command identity.Command
	if token, ok := original.SessionToken(); ok {
		command, plan, err = p.codec.MapSessionWithAuthority(context.Background(), a, 3, spec, token, owner)
	} else {
		cookie, _ := original.PreAuthCookie()
		command, plan, err = p.codec.MapPreAuthWithAuthority(context.Background(), a, 3, spec, cookie, owner)
	}
	if err != nil {
		t.Fatal(err)
	}
	return command, plan
}

func TestNativeMeteredCheckOriginalCustody(t *testing.T) {
	for _, variant := range []string{"preauth", "session"} {
		t.Run(variant, func(t *testing.T) {
			p, original, plan := nativeContributorFixture(t)
			if variant == "session" {
				config, command, declared, _ := nativeSessionFixture(t)
				var err error
				p, err = NewContributorWithSession(config.ContributorConfig, *config.Session)
				if err != nil {
					t.Fatal(err)
				}
				original, plan = command, declared
			}
			command, check := meteredCheckCommand(t, p, original, plan, "123456", 1)
			spec, _ := command.Feature()
			found := false
			for _, op := range p.FeatureOperations() {
				if op == spec.Operation {
					found = true
				}
			}
			if !found {
				t.Fatal("native check owner does not declare original profile")
			}
			if err := p.ValidateOTPAttemptCommand(command, check); err != nil {
				t.Fatal("complete original check custody rejected", err)
			}
			check.Mode = kernel.OTPConsume
			if p.ValidateOTPAttemptCommand(command, check) == nil {
				t.Fatal("checked custody promoted to consuming authority")
			}
		})
	}
}
