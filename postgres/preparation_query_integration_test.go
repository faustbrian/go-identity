//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// The kernel fixture uses opaque bytes, not an OTP interoperability oracle.
func (*preparedFeaturePhase) PrepareRequestKey(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
	return nil, identity.UnavailableError{}
}

func (p *preparedFeaturePhase) RestoreRequestKey(_ context.Context, b RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	if b.Admission.CommandID != p.requestOriginal.CommandID || !bytes.Equal(wire, []byte{0x91, 0x82, 0x73}) {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	return p.requestOriginal, nil
}

func testPreparedFeatureQuery(t *testing.T, ctx context.Context, c *Coordinator, phase *preparedFeaturePhase, command identity.Command, plan CommandPlan, installed ...bool) {
	t.Helper()
	if len(installed) == 0 || !installed[0] {
		// Install only on the legacy fixture path. Counter-profile callers have
		// already upgraded beyond admission; replaying this older check would
		// reject their valid profile-3/4 history.
		if _, err := c.pool.Raw().Exec(ctx, requestKeySQL+requestKeyPreparationSQL+admissionPreparationSchemaSQL); err != nil {
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
	output, generation, err := c.QueryFeaturePreparation(ctx, q, caller, *plan.Feature, phase)
	if err != nil || generation != 1 || len(output) != 17000 {
		t.Fatal("native output incorrectly requires a request-key mapping", err)
	}
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
	phase.requestOriginal = s.Binding
	recovered, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, *plan.Feature, phase)
	if err != nil || recovered.Binding != result.Binding || recovered.Outcome != result.Outcome || recovered.AuditEventID != result.AuditEventID || recovered.Feature == nil || *recovered.Feature != *result.Feature {
		t.Fatal("mapped recovery lost actual committed receipt", err)
	}
	// RecoveryQuery omits these immutable fields. The new native full-binding
	// comparison, not the ordinary query scope check, must fence substitution.
	for _, alter := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.PolicyID = "another-policy" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.CorrelationID = "another-correlation" },
	} {
		phase.requestOriginal = s.Binding
		alter(&phase.requestOriginal)
		got, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, *plan.Feature, phase)
		if err == nil || got.Binding.CommandID != "" {
			t.Fatal("native original with differing immutable journal binding disclosed")
		}
	}
	phase.requestOriginal = s.Binding
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
	testOriginalInputQuery(t, ctx, c, phase, command, plan, fields, input)
}

type originalInputReader interface {
	QueryRequestPreparation(context.Context, identity.RecoveryQuery, authorization.DecisionContext, FeatureRegistration, RequestKeyPreparationContributor) (RequestKeyPreparationBinding, []byte, error)
}

// SU-08: recovery needs only the immutable input, including before generation
// and after a classified rollback. Real journal transitions remain the sole
// outcome owner; an input read must never classify or execute the attempt.
func testOriginalInputQuery(t *testing.T, ctx context.Context, c *Coordinator, phase *preparedFeaturePhase, command identity.Command, plan CommandPlan, fields []identity.FeatureField, input []byte) {
	t.Helper()
	reader, ok := any(c).(originalInputReader)
	if !ok {
		t.Fatal("kernel has no password-free original-input read")
	}
	for _, state := range []string{"committed", "input-only", "pending", "started-without-output", "aborted"} {
		t.Run(state, func(t *testing.T) {
			s, _ := command.Feature()
			p := plan
			p.Audits = append([]AuditPlan(nil), plan.Audits...)
			if state != "committed" {
				s.Binding.CommandID, _ = identity.NewCommandID()
				s.Binding.CorrelationID = string(s.Binding.CommandID)
				// Each constructed state needs its own counter allowance. Sharing
				// the committed tenant would exercise quota denial, not recovery.
				s.Binding.TenantID = identity.TenantID("original-" + s.Binding.CommandID)
			}
			scope := RequestKeyScope{TenantID: s.Binding.TenantID, ActorID: s.Binding.ActorID, ActorKind: s.Binding.ActorKind, Method: "POST", RouteID: s.Binding.OperationID}
			digest, safe, err := requestIntentFingerprint(scope, fields, 7, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			if state != "committed" {
				seed, err := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, s.Binding.RecordID, p.Audits[0].RetentionClass, true)
				if err != nil {
					t.Fatal(err)
				}
				p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, p.SubjectType, seed)
				if err != nil {
					t.Fatal(err)
				}
				id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
				identityDigest := requestPreparationIdentity(*p.Feature)
				keyDigest := sha256.Sum256(id)
				if _, err := c.pool.Raw().Exec(ctx, `INSERT INTO identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest,command_id,fingerprint,fingerprint_key_version,safe_fields,request_preparation_identity,request_preparation_ciphertext) VALUES('original',$1,$2,$3,'POST',$4,$5,$6,$7,1,$8,$9,$10)`, string(s.Binding.TenantID), string(s.Binding.ActorID), string(s.Binding.ActorKind), s.Binding.OperationID, keyDigest[:], id, digest[:], safe, identityDigest[:], input); err != nil {
					t.Fatal(err)
				}
				original := featureCodecCommand(t, s)
				phase.declaration = p
				defer func() { phase.declaration, phase.beforeGenerate, phase.fail = plan, nil, false }()
				switch state {
				case "pending":
					claim, admitted, owner, err := c.prepareFeaturePreparation(original, p)
					if err != nil {
						t.Fatal(err)
					}
					reservation, _, err := c.startFeaturePreparation(ctx, original, claim, admitted, owner, [16]byte{1}, true)
					if err != nil || reservation.journal.disposition != journalOwned {
						t.Fatal("pending journal reservation", err)
					}
				case "started-without-output":
					phase.beforeGenerate = func(context.Context, identity.Command, uint64) error { return identity.UnavailableError{} }
					result, err := c.ExecutePreparedFeature(ctx, original, p)
					if err == nil || result.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("original uncertain generation", err)
					}
				case "aborted":
					phase.fail = true
					result, err := c.ExecutePreparedFeature(ctx, original, p)
					if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("original rollback", err)
					}
				}
			}
			q, caller := queryInputs(s.Binding)
			id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
			snapshot := func() string {
				var wire string
				if err := c.pool.Raw().QueryRow(ctx, `SELECT coalesce((SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1),'absent')`, id).Scan(&wire); err != nil {
					t.Fatal(err)
				}
				return wire
			}
			before, generated, restored := snapshot(), phase.generated.Load(), phase.restored.Load()
			binding, wire, err := reader.QueryRequestPreparation(ctx, q, caller, *p.Feature, phase)
			if err != nil || binding.Admission.CommandID != q.CommandID || binding.PolicyVersion != 7 || binding.IntentDigest != digest || !bytes.Equal(wire, input) {
				t.Fatal("original input unavailable for recovery", err)
			}
			wire[0] ^= 1
			_, again, err := reader.QueryRequestPreparation(ctx, q, caller, *p.Feature, phase)
			if err != nil || !bytes.Equal(again, input) {
				t.Fatal("input read mutated immutable history", err)
			}
			if state != "committed" {
				if got, err := c.QueryPreparedFeature(ctx, q, caller, *p.Feature, phase); err == nil || got.InputCiphertext != nil || got.OutputCiphertext != nil {
					t.Fatal("legacy committed-output query was broadened")
				}
			}
			for _, mutate := range []func(*identity.RecoveryQuery){
				func(q *identity.RecoveryQuery) { q.TenantID = "other" },
				func(q *identity.RecoveryQuery) { q.ActorID = "other" },
				func(q *identity.RecoveryQuery) { q.OperationID = "identity.otp.check" },
			} {
				other := q
				mutate(&other)
				binding, wire, err := reader.QueryRequestPreparation(ctx, other, callerForQuery(caller, other), *p.Feature, phase)
				if err == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
					t.Fatal("foreign input disclosed")
				}
			}
			binding, wire, err = reader.QueryRequestPreparation(ctx, q, caller, *p.Feature, &preparedFeaturePhase{})
			if err == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
				t.Fatal("descriptor spoof read original input")
			}
			if state != "input-only" {
				for _, mutate := range []func(*identity.RecoveryQuery){
					func(q *identity.RecoveryQuery) { q.UserID = "foreign-user" },
					func(q *identity.RecoveryQuery) { q.RecordID = "foreign-record" },
				} {
					other := q
					mutate(&other)
					binding, wire, err := reader.QueryRequestPreparation(ctx, other, callerForQuery(caller, other), *p.Feature, phase)
					if err == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
						t.Fatal("claim subject/record mismatch disclosed input")
					}
				}
			}
			for _, alter := range []func(*Coordinator){
				func(c *Coordinator) { c.keys.retained = nil },
				func(c *Coordinator) {
					keys, err := NewRequestKeyConfig(c.requestKeys.Namespace, [32]byte{99}, c.requestKeys.Policy)
					if err != nil {
						t.Fatal(err)
					}
					c.requestKeys = &keys
				},
				func(c *Coordinator) {
					c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
						return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
					})}
				},
			} {
				other := *c
				alter(&other)
				reader := any(&other).(originalInputReader)
				binding, wire, err := reader.QueryRequestPreparation(ctx, q, caller, *p.Feature, phase)
				if err == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
					t.Fatal("incompatible key/current policy disclosed input")
				}
			}
			cancelled, stop := context.WithCancel(ctx)
			stop()
			if binding, wire, err := reader.QueryRequestPreparation(cancelled, q, caller, *p.Feature, phase); !errors.Is(err, context.Canceled) || binding != (RequestKeyPreparationBinding{}) || wire != nil {
				t.Fatal("cancelled query disclosed custody")
			}
			if snapshot() != before || phase.generated.Load() != generated || phase.restored.Load() != restored {
				t.Fatal("input query changed execution or generation")
			}
		})
	}
}
