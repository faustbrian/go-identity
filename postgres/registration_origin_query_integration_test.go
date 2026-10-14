//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

type registrationInputReader interface {
	QueryRegistrationPreparation(context.Context, identity.RecoveryQuery, authorization.DecisionContext, FeatureRegistration, RequestKeyPreparationContributor) (RequestKeyPreparationBinding, []byte, error)
}

// Real kernel registration and journal commit precede this fixture. Opaque
// synthetic input tests custody provenance, not mailbox/crypto interoperability.
func testRegistrationOriginInput(t *testing.T, ctx context.Context, c *Coordinator, owner *registrationTestPhase, original identity.CommandBinding, plan CommandPlan) {
	t.Helper()
	reader, ok := any(c).(registrationInputReader)
	if !ok {
		t.Fatal("kernel has no confirmation-owned original signup input read")
	}
	if _, err := c.pool.Raw().Exec(ctx, requestKeySQL+requestKeyPreparationSQL); err != nil {
		t.Fatal(err)
	}
	// The full registration matrix's issuance subtest may already install the
	// optional preparation history; the focused origin slice must install it.
	var preparationInstalled bool
	if err := c.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='identity' AND table_name='commands' AND column_name='preparation_profile')`).Scan(&preparationInstalled); err != nil {
		t.Fatal(err)
	}
	if !preparationInstalled {
		if _, err := c.pool.Raw().Exec(ctx, preparationSchemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if dc.Request.Subject.ID != "confirmation-service" || dc.Request.Subject.Kind != authorization.SubjectServiceAccount || dc.Request.Action != "identity.email.verification-confirm" || dc.Request.Resource.Type != "identity.user" || dc.Request.Resource.ID != authorization.ResourceID(owner.intent.Creation.Binding.UserID) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	config, err := NewRequestKeyConfig("registration-original", [32]byte{2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	c.requestKeys, c.queryPolicy, c.commandRead = &config, &policy, c.readCommand
	scope := RequestKeyScope{TenantID: original.TenantID, ActorID: original.ActorID, ActorKind: original.ActorKind, Method: "POST", RouteID: original.OperationID}
	fields := []identity.FeatureField{{Name: "original", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "intent"}}}
	digest, safe, err := requestIntentFingerprint(scope, fields, 7, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	namespace, preparation := requestNamespaceIdentity(config.Namespace, [32]byte{2}), requestPreparationIdentity(*plan.Feature)
	input := []byte{0x91, 0x82, 0x73}
	if _, err := c.pool.Raw().Exec(ctx, `INSERT INTO identity.request_key_namespaces VALUES($1,$2)`, config.Namespace, namespace[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Raw().Exec(ctx, `INSERT INTO identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest,command_id,fingerprint,fingerprint_key_version,safe_fields,request_preparation_identity,request_preparation_ciphertext) VALUES($1,$2,$3,$4,'POST',$5,$6,$7,$8,1,$9,$10,$11)`, config.Namespace, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.RouteID, bytes.Repeat([]byte{2}, 32), mustCommandBytes(t, original.CommandID), digest[:], safe, preparation[:], input); err != nil {
		t.Fatal(err)
	}
	q := identity.RecoveryQuery{CommandID: original.CommandID, TenantID: original.TenantID, UserID: owner.intent.Creation.Binding.UserID, ActorID: "confirmation-service", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.email.verification-confirm"}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(q.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Action: authorization.Action(q.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
	snapshot := func() string {
		var value string
		if e := c.pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1`, mustCommandBytes(t, original.CommandID)).Scan(&value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	before := snapshot()
	for n := 0; n < 2; n++ {
		binding, wire, e := reader.QueryRegistrationPreparation(ctx, q, caller, *plan.Feature, owner)
		if e != nil || binding.Scope != scope || binding.PolicyVersion != 7 || binding.Admission.CommandID != original.CommandID || binding.IntentDigest != digest || !bytes.Equal(wire, input) {
			t.Fatal("confirmation lost original scope or custody", e)
		}
		wire[0] ^= 1
		clear(wire)
	}
	for _, mutate := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.UserID = "other-user" },
		func(q *identity.RecoveryQuery) { q.TenantID = "other-tenant" },
		func(q *identity.RecoveryQuery) { q.CommandID, _ = identity.NewCommandID() },
		func(q *identity.RecoveryQuery) { q.ActorID = original.ActorID; q.ActorKind = original.ActorKind },
		func(q *identity.RecoveryQuery) { q.OperationID = "identity.password.signup" },
	} {
		other := q
		mutate(&other)
		binding, wire, e := reader.QueryRegistrationPreparation(ctx, other, callerForQuery(caller, other), *plan.Feature, owner)
		if e == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
			t.Fatal("foreign current confirmation scope disclosed original input")
		}
	}
	if binding, wire, e := reader.QueryRegistrationPreparation(ctx, q, caller, *plan.Feature, &registrationTestPhase{}); e == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
		t.Fatal("foreign native owner disclosed original input")
	}
	allow := *c
	allow.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	otherUser := q
	otherUser.UserID = "other-user"
	if binding, wire, e := allow.QueryRegistrationPreparation(ctx, otherUser, callerForQuery(caller, otherUser), *plan.Feature, owner); e == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
		t.Fatal("policy allow replaced positive original registration binding")
	}
	for _, alter := range []func(*Coordinator){
		func(c *Coordinator) { c.keys.retained = nil },
		func(c *Coordinator) { config := *c.requestKeys; config.Namespace = "foreign"; c.requestKeys = &config },
		func(c *Coordinator) {
			c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
			})}
		},
	} {
		other := *c
		alter(&other)
		if binding, wire, e := other.QueryRegistrationPreparation(ctx, q, caller, *plan.Feature, owner); e == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil {
			t.Fatal("unavailable provenance or denied current policy disclosed input")
		}
	}
	for _, state := range []string{"pending", "aborted"} {
		t.Run(state, func(t *testing.T) {
			id := mustCommandBytes(t, original.CommandID)
			var result []byte
			var terminal time.Time
			if e := c.pool.Raw().QueryRow(ctx, `SELECT result,terminal_at FROM identity.commands WHERE command_id=$1`, id).Scan(&result, &terminal); e != nil {
				t.Fatal(e)
			}
			defer clear(result)
			defer func() {
				if _, e := c.pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='committed',result_version=1,terminal_class='committed',result=$1,terminal_at=$2 WHERE command_id=$3`, result, terminal, id); e != nil {
					t.Error("original terminal fixture restoration failed")
				}
			}()
			if state == "pending" {
				if _, e := c.pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='pending',result_version=NULL,terminal_class=NULL,result=NULL,terminal_at=NULL WHERE command_id=$1`, id); e != nil {
					t.Fatal(e)
				}
			} else {
				// A canonical aborted receipt keeps the original frozen feature,
				// not a malformed or merely relabelled success result.
				claim, e := prepareClaim(owner.expected, [32]byte{1})
				if e != nil {
					t.Fatal(e)
				}
				encoded, e := encodeJournalResult(claim, identity.CommandResult{Binding: original, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: plan.Feature.Operation}})
				if e != nil {
					t.Fatal(e)
				}
				defer clear(encoded)
				if _, e := c.pool.Raw().Exec(ctx, `UPDATE identity.commands SET state='aborted',terminal_class='denied',result=$1 WHERE command_id=$2`, encoded, id); e != nil {
					t.Fatal(e)
				}
			}
			binding, wire, e := reader.QueryRegistrationPreparation(ctx, q, caller, *plan.Feature, owner)
			var denied identity.ForbiddenError
			if !errors.As(e, &denied) || binding != (RequestKeyPreparationBinding{}) || wire != nil {
				t.Fatal("noncommitted original command disclosed registration input", e)
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if binding, wire, e := reader.QueryRegistrationPreparation(cancelled, q, caller, *plan.Feature, owner); !errors.Is(e, context.Canceled) || binding != (RequestKeyPreparationBinding{}) || wire != nil {
		t.Fatal("cancelled origin lookup disclosed custody")
	}
	var readers sync.WaitGroup
	for range 6 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			binding, wire, e := reader.QueryRegistrationPreparation(ctx, q, caller, *plan.Feature, owner)
			defer clear(wire)
			if e != nil || binding.Scope != scope || !bytes.Equal(wire, input) {
				t.Error("concurrent confirmation custody crossed", e)
			}
		}()
	}
	readers.Wait()
	if snapshot() != before {
		t.Fatal("confirmation origin read mutated original command")
	}
}
