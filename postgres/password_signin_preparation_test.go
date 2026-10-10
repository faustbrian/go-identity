package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This participant observes native command transport only, not password
// comparison, pre-auth policy or production session issuance.
type signinPreparationParticipant struct{ outputPreparationParticipant }

func (*signinPreparationParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password.store", Version: 1}
}
func (*signinPreparationParticipant) ValidateFeaturePreparation(c identity.Command, _ CommandPlan) error {
	p, b, ok := c.PasswordSigninCustody()
	if !ok || p.Len() == 0 || b.Token() == "" {
		return invalidPreparation()
	}
	return nil
}

func TestPasswordSigninPreparationSelectsOriginalPairedVariant(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		c, _, plan := coordinatorFixture(t)
		s := passwordSigninCodecSpec(anonymous)
		owner := &signinPreparationParticipant{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}}}
		entries := []Contributor{&riskPassiveProbe{registryContributor{plan.Contributors[0]}}, &riskPassiveProbe{registryContributor{plan.Contributors[1]}}, &riskPassiveProbe{registryContributor{plan.Contributors[2]}}, owner}
		registry, err := NewContributorRegistry(entries)
		if err != nil {
			t.Fatal(err)
		}
		c.registry = registry
		plan.Contributors = registry.Descriptors()
		plan.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: s.Operation}
		plan.SubjectType = "authentication"
		plan.Lifecycle = &LifecyclePlan{EventType: "password.signin.v1"}
		plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "password.signin", "standard"
		seed, err := securityMutationAudit(t.Context(), s.Binding, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", "password.signin", plan.SubjectType, featureTargetID(s.Binding), "standard", true)
		if err != nil {
			t.Fatal(err)
		}
		plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, plan.SubjectType, seed)
		if err != nil {
			t.Fatal(err)
		}
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
		command, secret := passwordSigninCodecCommand(t, s, []byte("synthetic-signin"), wire)
		q, admitted, phase, err := c.prepareFeaturePreparation(command, plan)
		if err != nil || admitted == nil || phase != owner || q.source == nil || admitted.binding != s.Binding {
			t.Fatal("native preparation rejected paired signin", err)
		}
		borrowed, cookie, ok := q.source.PasswordSigninCustody()
		if !ok || borrowed.Len() != secret.Len() || cookie.Token() != wire {
			t.Fatal("preparation dropped original paired custody")
		}
		prepared, err := c.PrepareCommandPlan(s.Binding, command, plan)
		if err != nil || prepared.Digest == ([32]byte{}) || prepared.Feature.Operation != s.Operation {
			t.Fatal("final plan denied disjoint signin", err)
		}
		if _, _, _, err := c.prepareFeaturePreparation(featureCodecCommand(t, s), plan); err == nil {
			t.Fatal("plain metadata admitted as original signin")
		}
		secret.Destroy()
		if _, _, _, err := c.prepareFeaturePreparation(command, plan); err == nil {
			t.Fatal("destroyed original secret admitted")
		}
	}
}
