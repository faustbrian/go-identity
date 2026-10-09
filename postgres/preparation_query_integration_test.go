//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// The kernel fixture uses opaque bytes, not an OTP interoperability oracle.
func (*preparedFeaturePhase) PrepareRequestKey(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
	return nil, identity.UnavailableError{}
}

func testPreparedFeatureQuery(t *testing.T, ctx context.Context, c *Coordinator, phase *preparedFeaturePhase, command identity.Command, plan CommandPlan, installed ...bool) {
	t.Helper()
	if len(installed) == 0 || !installed[0] {
		if _, err := c.pool.Raw().Exec(ctx, requestKeySQL+requestKeyPreparationSQL); err != nil {
			t.Fatal(err)
		}
	}
	policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	config, err := NewRequestKeyConfig("original", [32]byte{2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	c.requestKeys, c.queryPolicy = &config, &policy
	c.commandRead = c.readCommand
	result, err := c.ExecutePreparedFeature(ctx, command, plan)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real prepared commit", err)
	}
	s, _ := command.Feature()
	q, caller := queryInputs(s.Binding)
	scope := RequestKeyScope{TenantID: q.TenantID, ActorID: q.ActorID, ActorKind: q.ActorKind, Method: "POST", RouteID: q.OperationID}
	if r, err := c.QueryPreparedFeature(ctx, q, caller, *plan.Feature, phase); err == nil || r.InputCiphertext != nil || r.OutputGeneration != 0 {
		t.Fatal("committed journal without original input accepted")
	}
	fields := []identity.FeatureField{{Name: "original", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "intent"}}}
	digest, safe, err := requestIntentFingerprint(scope, fields, 7, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte{0x91, 0x82, 0x73}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	namespace := requestNamespaceIdentity("original", [32]byte{2})
	identityDigest := requestPreparationIdentity(*plan.Feature)
	if _, err := c.pool.Raw().Exec(ctx, `INSERT INTO identity.request_key_namespaces VALUES('original',$1) ON CONFLICT DO NOTHING`, namespace[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Raw().Exec(ctx, `INSERT INTO identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest,command_id,fingerprint,fingerprint_key_version,safe_fields,request_preparation_identity,request_preparation_ciphertext) VALUES('original',$1,$2,$3,'POST',$4,$5,$6,$7,1,$8,$9,$10)`, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.RouteID, bytes.Repeat([]byte{2}, 32), id, digest[:], safe, identityDigest[:], input); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var value string
		if err := c.pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	got, err := c.QueryPreparedFeature(ctx, q, caller, *plan.Feature, phase)
	if err != nil || got.InputBinding.PolicyVersion != 7 || got.InputBinding.IntentDigest != digest || got.InputBinding.Admission.CommandID != q.CommandID || got.InputBinding.Scope != scope || got.OutputGeneration != 1 || !bytes.Equal(got.InputCiphertext, input) || len(got.OutputCiphertext) != 17000 {
		t.Fatal("original custody/provenance lost", err)
	}
	got.InputCiphertext[0] ^= 1
	got.OutputCiphertext[0] ^= 1
	again, err := c.QueryPreparedFeature(ctx, q, caller, *plan.Feature, phase)
	if err != nil || again.InputCiphertext[0] != input[0] || bytes.Equal(again.OutputCiphertext, got.OutputCiphertext) {
		t.Fatal("returned bytes mutated history", err)
	}
	for _, change := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.TenantID = "other" }, func(q *identity.RecoveryQuery) { q.UserID = "other" }, func(q *identity.RecoveryQuery) { q.ActorID = "other" }, func(q *identity.RecoveryQuery) { q.RecordID = "other" }, func(q *identity.RecoveryQuery) { q.OperationID = "identity.otp.check" },
	} {
		other := q
		change(&other)
		r, err := c.QueryPreparedFeature(ctx, other, callerForQuery(caller, other), *plan.Feature, phase)
		if err == nil || r.OutputGeneration != 0 || r.InputCiphertext != nil || r.OutputCiphertext != nil {
			t.Fatal("foreign scope disclosed custody")
		}
	}
	foreign := &preparedFeaturePhase{}
	if r, err := c.QueryPreparedFeature(ctx, q, caller, *plan.Feature, foreign); err == nil || r.OutputGeneration != 0 {
		t.Fatal("descriptor spoof accepted")
	}
	for _, alter := range []func(*Coordinator){
		func(c *Coordinator) { config := *c.requestKeys; config.Namespace = "other"; c.requestKeys = &config },
		func(c *Coordinator) { c.keys.retained = nil },
	} {
		other := *c
		alter(&other)
		if r, err := other.QueryPreparedFeature(ctx, q, caller, *plan.Feature, phase); err == nil || r.InputCiphertext != nil || r.OutputGeneration != 0 {
			t.Fatal("incompatible native configuration accepted")
		}
	}
	denied := *c
	denied.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
	})}
	if r, err := denied.QueryPreparedFeature(ctx, q, caller, *plan.Feature, phase); err == nil || r.InputCiphertext != nil {
		t.Fatal("current denial disclosed custody")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if r, err := c.QueryPreparedFeature(canceled, q, caller, *plan.Feature, phase); !errors.Is(err, context.Canceled) || r.OutputGeneration != 0 {
		t.Fatal("cancellation lost", err)
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			r, err := c.QueryPreparedFeature(ctx, q, caller, *plan.Feature, phase)
			if err != nil || r.OutputGeneration != 1 || !bytes.Equal(r.InputCiphertext, input) {
				t.Error("concurrent custody crossed", err)
			}
		}()
	}
	wait.Wait()
	if snapshot() != before || phase.generated.Load() != 1 || phase.restored.Load() != 1 {
		t.Fatal("query changed original workflow")
	}
}
