package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func TestRequestPreparationClaimKeepsOriginalScopeWithoutOutcome(t *testing.T) {
	s := featureCodecSpec()
	command := featureCodecCommand(t, s)
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := queryInputs(s.Binding)
	feature := FeatureRegistration{Operation: s.Operation}
	state := "pending"
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(-time.Second)
	base := commandObservation{tenant: string(q.TenantID), purpose: q.OperationID, scope: claim.safeFields, fingerprint: queryFingerprint(), state: &state, until: &until, now: now}
	// Expired ownership is still historical custody, not fresh execution. The
	// outcome/reconciliation owner, not this read, decides whether work may resume.
	for profile := int16(1); profile <= 4; profile++ {
		if err := requestPreparationClaimScope(q, feature, base, profile); err != nil {
			t.Fatal("original pending scope lost", err)
		}
	}
	for _, mutate := range []func(*commandObservation){
		func(o *commandObservation) { o.scope = nil },
		func(o *commandObservation) { o.fingerprint = nil },
		func(o *commandObservation) { o.retired = true },
		func(o *commandObservation) { o.tenant = "foreign" },
		func(o *commandObservation) { o.purpose = "foreign" },
		func(o *commandObservation) { o.state = nil },
		func(o *commandObservation) { value := "committed"; o.state = &value },
		func(o *commandObservation) { o.until = nil },
		func(o *commandObservation) { o.now = time.Time{} },
		func(o *commandObservation) { value := int32(1); o.resultVersion = &value },
		func(o *commandObservation) { value := "denied"; o.class = &value },
		func(o *commandObservation) { o.result = []byte{1} },
		func(o *commandObservation) { o.plan = []byte{1} },
	} {
		changed := base
		mutate(&changed)
		if err := requestPreparationClaimScope(q, feature, changed, 1); err == nil {
			t.Fatal("corrupt/retired claim granted input disclosure")
		}
	}
	for _, profile := range []int16{0, 5} {
		if requestPreparationClaimScope(q, feature, base, profile) == nil {
			t.Fatal("unregistered pending preparation accepted")
		}
	}
	for _, mutate := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(q *identity.RecoveryQuery) { q.UserID = "foreign" },
		func(q *identity.RecoveryQuery) { q.AnonymousFlowID = "foreign" },
		func(q *identity.RecoveryQuery) { q.ActorID = "foreign" },
		func(q *identity.RecoveryQuery) { q.ActorKind = authorization.SubjectAPIKey },
		func(q *identity.RecoveryQuery) { q.RecordID = "foreign" },
		func(q *identity.RecoveryQuery) { q.LinkMode++ },
	} {
		other := q
		mutate(&other)
		if requestPreparationClaimScope(other, feature, base, 1) == nil {
			t.Fatal("retargeted claim accepted")
		}
	}
}

func TestRequestPreparationQueryRejectsZeroComposition(t *testing.T) {
	var c *Coordinator
	for _, ctx := range []context.Context{nil, context.Background()} {
		binding, input, err := c.QueryRequestPreparation(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}, FeatureRegistration{}, nil)
		if err == nil || binding != (RequestKeyPreparationBinding{}) || input != nil {
			t.Fatal("invalid composition disclosed input")
		}
	}
}
