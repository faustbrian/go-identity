package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

type signupInputPreparationParticipant struct{ outputPreparationParticipant }

func (*signupInputPreparationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}

func (*signupInputPreparationParticipant) ValidateFeaturePreparation(c identity.Command, _ CommandPlan) error {
	p, cookie, ok := c.PasswordSignupInputCustody()
	if !ok || p.Len() == 0 || cookie.Token() == "" {
		return invalidPreparation()
	}
	return nil
}

func TestOriginalSignupPreparationKeepsExecutionClosed(t *testing.T) {
	c, _, plan := coordinatorFixture(t)
	s := passwordSignupCodecSpec(true)
	owner := &signupInputPreparationParticipant{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}}}
	r, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{plan.Contributors[0]}}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	plan.Contributors = r.Descriptors()
	plan.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: s.Operation}
	plan.SubjectType, plan.SignupAcceptance = "user", true
	plan.Lifecycle = &LifecyclePlan{EventType: "user.created.v1"}
	plan.Audits[0].EventType, plan.Audits[0].RetentionClass = s.Operation.OperationID, "protected"
	seed, err := securityMutationAudit(t.Context(), s.Binding, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", s.Operation.OperationID, "user", s.Binding.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "user", seed)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := primitive.NewSecret([]byte(" synthetic original\x00\xffsignup "))
	defer p.Destroy()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{25}, 32))
	command, err := identity.NewFeaturePasswordSignupInputCommand(s, p, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := c.PrepareFeaturePreparationPlan(command, plan)
	if err != nil || prepared.Digest == ([32]byte{}) {
		t.Fatal("original input requires a generated verifier", err)
	}
	q, admitted, selected, err := c.prepareFeaturePreparation(command, prepared)
	if err != nil || admitted == nil || selected != owner || q.source == nil {
		t.Fatal("original signup preparation lost ownership", err)
	}
	borrowed, cookie, ok := q.source.PasswordSignupInputCustody()
	if !ok || borrowed.Len() != p.Len() || cookie.Token() != wire {
		t.Fatal("preparation discarded original custody")
	}
	if bytes.Contains(q.canonical, []byte(wire)) || bytes.Contains(q.safeFields, []byte(wire)) || bytes.Contains(q.canonical, []byte("synthetic original")) {
		t.Fatal("original custody entered journal evidence")
	}
	if _, err := c.PrepareCommandPlan(s.Binding, command, prepared); err == nil {
		t.Fatal("original input became ordinary execution")
	}
	if reservation, _, err := c.ReserveCommand(t.Context(), s.Binding, command, prepared); err == nil || reservation != (Reservation{}) {
		t.Fatal("original input obtained ordinary reservation")
	}
	p.Destroy()
	if _, err := c.PrepareFeaturePreparationPlan(command, plan); err == nil {
		t.Fatal("destroyed original input admitted")
	}
}

func TestOriginalSignupClaimBindsRawCustodyAndRetainedKeys(t *testing.T) {
	s := passwordSignupCodecSpec(true)
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{26}, 32))
	makeCommand := func(candidate []byte, cookie string) identity.Command {
		p, err := primitive.NewSecret(candidate)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Destroy)
		c, err := identity.NewFeaturePasswordSignupInputCommand(s, p, auth.NewBearerCredential(cookie))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	command := makeCommand([]byte(" original candidate "), wire)
	original, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal("original input cannot bind journal intent", err)
	}
	retained, err := prepareClaim(command, [32]byte{1})
	if err != nil || !bytes.Equal(original.canonical, retained.canonical) {
		t.Fatal("retained original intent changed", err)
	}
	rotated, err := prepareClaim(command, [32]byte{2})
	if err != nil || bytes.Equal(original.canonical, rotated.canonical) || !bytes.Equal(original.safeFields, rotated.safeFields) {
		t.Fatal("original custody omitted retained-key binding", err)
	}
	for _, changed := range []identity.Command{makeCommand([]byte("original candidate"), wire), makeCommand([]byte(" original candidate "), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{27}, 32)))} {
		q, err := prepareClaim(changed, [32]byte{1})
		if err != nil || bytes.Equal(q.canonical, original.canonical) || !bytes.Equal(q.safeFields, original.safeFields) {
			t.Fatal("changed original input reused intent", err)
		}
	}
}
