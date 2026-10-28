package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

func apiKeyVerificationPlanFixture(t *testing.T, anonymous bool) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	_, _, p := featurePlanFixture(t)
	b := codecBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.apikey.verify", "apikey-verify-v1", ""
	b.ActorKind, b.ActorID = authorization.SubjectAPIKey, "key-a"
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	p.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}, Operation: op}
	p.Contributors[len(p.Contributors)-1] = p.Feature.Contributor
	p.SubjectType = "api_key"
	p.Lifecycle = &LifecyclePlan{EventType: "api_key.permissions_changed.v1"}
	p.APIKeyVerification = &APIKeyVerificationPlan{KeyVersion: 7}
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.api_key.authenticate", "protected"
	update := p.Audits[0]
	update.EventType, update.EventIndex = "identity.api_key.update", 1
	p.Audits = append(p.Audits, update)
	if anonymous {
		b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
		b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "api-key-verifier"
		b.SchemaID = "apikey-verify-unknown-v1"
		p.Feature.Operation.SchemaID, p.Feature.Operation.SubjectRequirement = b.SchemaID, identity.FeatureSubjectAnonymousFlow
		p.APIKeyVerification.KeyVersion = 0
		p.SubjectType = "authentication_attempt"
		p.Audits = p.Audits[:1]
	}
	if err := b.ValidateFor(p.Feature.Operation); err != nil {
		t.Fatal(err)
	}
	return b, p
}

func TestAPIKeyVerificationPlanPreservesReadOnlyAttemptAndConditionalNarrow(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		b, p := apiKeyVerificationPlanFixture(t, anonymous)
		fp := [32]byte{9}
		wire, err := encodeFeaturePlan(b, fp, p)
		if err != nil {
			t.Fatal("closed verification declaration rejected", err)
		}
		got, err := decodeFeaturePlan(b, fp, wire)
		p.Digest = sha256.Sum256(wire)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatal("verification lost frozen attempt/effect declaration", err)
		}
		if _, err := KernelPlanDigest(b, fp, p); err == nil {
			t.Fatal("verification entered ordinary kernel profile")
		}
		if !anonymous {
			p.APIKeyVerification.KeyVersion++
			digest, err := FeaturePlanDigest(b, fp, p)
			if err != nil || digest == got.Digest {
				t.Fatal("possible Narrow version was not frozen")
			}
		}
		for _, bad := range [][]byte{append(bytes.Clone(wire), 0), wire[:len(wire)-1], bytes.Replace(wire, []byte("identity-apikey-verification-v1"), []byte("identity-apikey-verification-v2"), 1)} {
			if got, err := decodeFeaturePlan(b, fp, bad); err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
				t.Fatal("malformed verification declaration escaped")
			}
		}
	}
}

func TestAPIKeyVerificationPlanCannotReclassifyAnotherFeature(t *testing.T) {
	cases := []struct {
		name   string
		change func(*identity.CommandBinding, *CommandPlan)
	}{
		{"owner", func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Operation.Owner = "identity/password" }},
		{"operation", func(b *identity.CommandBinding, p *CommandPlan) {
			b.OperationID = "identity.apikey.create"
			p.Feature.Operation.OperationID = b.OperationID
		}},
		{"schema", func(b *identity.CommandBinding, p *CommandPlan) {
			b.SchemaID = "caller-schema"
			p.Feature.Operation.SchemaID = b.SchemaID
		}},
		{"contributor", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.Owner = "identity/password/postgres"
		}},
		{"human-actor", func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorKind = authorization.SubjectUser }},
		{"key-version-zero", func(_ *identity.CommandBinding, p *CommandPlan) { p.APIKeyVerification.KeyVersion = 0 }},
		{"key-version-overflow", func(_ *identity.CommandBinding, p *CommandPlan) { p.APIKeyVerification.KeyVersion = ^uint64(0) }},
		{"invented-mutation", func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.AfterVersion = 1 }},
		{"invented-event", func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "api_key.authenticated.v1" }},
		{"missing-auth-audit", func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits = p.Audits[1:] }},
		{"unprotected", func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "standard" }},
		{"unrelated-update", func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[1].EventType = "identity.api_key.create" }},
		{"counter-side-channel", func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{1}}
		}},
		{"other-effect", func(_ *identity.CommandBinding, p *CommandPlan) { p.SignupAcceptance = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, p := apiKeyVerificationPlanFixture(t, false)
			tc.change(&b, &p)
			if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign/ambiguous verification declaration accepted")
			}
		})
	}
	b, p := apiKeyVerificationPlanFixture(t, true)
	p.APIKeyVerification.KeyVersion = 1
	if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
		t.Fatal("unknown-key attempt could mutate an invented key")
	}
}

func TestAPIKeyVerificationDoesNotCaptureForeignFeatureHistory(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, delivery := range []bool{false, true} {
			for _, variant := range []string{"foreign-owner", "legacy-schema", "other-version"} {
				t.Run(variant+map[bool]string{false: "-user", true: "-anonymous"}[anonymous]+map[bool]string{false: "-plain", true: "-delivery"}[delivery], func(t *testing.T) {
					b, p := apiKeyVerificationPlanFixture(t, anonymous)
					p.APIKeyVerification = nil
					switch variant {
					case "foreign-owner":
						p.Feature.Operation.Owner = "identity/custom"
						p.Feature.Contributor.Owner = "identity/custom/postgres"
					case "legacy-schema":
						b.SchemaID, p.Feature.Operation.SchemaID = "legacy-verify-v1", "legacy-verify-v1"
					case "other-version":
						b.SchemaVersion, p.Feature.Operation.SchemaVersion = 2, 2
					}
					p.Contributors[len(p.Contributors)-1] = p.Feature.Contributor
					if delivery {
						descriptor := ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.effects", Version: 1}
						p.Contributors = append(p.Contributors, descriptor)
						subject := string(b.UserID)
						if anonymous {
							subject = b.AnonymousFlowID
						}
						p.Delivery = &DeliveryPlan{Contributor: descriptor, Intents: []DeliveryIntentPlan{{EffectID: "delivery-effect-a", EffectIndex: 0, IntentDigest: [32]byte{7}, Purpose: "security-notification", SubjectID: subject, TemplateID: "security-notification", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}}
					}
					fingerprint := [32]byte{9}
					wire, err := encodeFeaturePlan(b, fingerprint, p)
					if err != nil {
						t.Fatal("previous generic descriptor no longer encodes", err)
					}
					got, err := decodeFeaturePlan(b, fingerprint, wire)
					p.Digest = sha256.Sum256(wire)
					if err != nil || !reflect.DeepEqual(got, p) {
						t.Fatal("verification operation name captured another owner's retained history", err)
					}
					testAPIKeyVerificationGenericHistory(t, b, p, wire, fingerprint)
				})
			}
		}
	}
}

func testAPIKeyVerificationGenericHistory(t *testing.T, b identity.CommandBinding, p CommandPlan, wire []byte, fingerprint [32]byte) {
	t.Helper()
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "committed"} {
		c, _, _ := featurePlanFixture(t)
		c.registry = nil
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		now := time.Now().UTC().Truncate(time.Microsecond)
		until := now.Add(time.Second)
		stored := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, state: &state, now: now, until: &until, plan: wire, fingerprint: bytes.Clone(fingerprint[:])}
		expected := identity.CommitOutcomeInProgress
		if state == "committed" {
			expected = identity.CommitOutcomeCommitted
			version, class := int32(1), "committed"
			stored.resultVersion, stored.class = &version, &class
			stored.result, err = encodeJournalResult(claim, identity.CommandResult{Binding: b, Outcome: expected, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: p.Feature.Operation}})
			if err != nil {
				t.Fatal(err)
			}
		}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return stored, nil }
		query, caller := queryInputs(b)
		got, err := c.QueryCommand(t.Context(), query, caller)
		if err != nil || got.Validate() != nil || got.Binding != b || got.Outcome != expected || got.Feature == nil || *got.Feature != p.Feature.Operation {
			t.Fatal("generic pending/terminal metadata became unreadable", err)
		}
		if state == "committed" {
			recovered, err := c.RecoverFeatureCommand(t.Context(), query, caller)
			if err != nil || recovered.Validate() != nil || recovered.Binding != b || recovered.Outcome != expected || recovered.AuditEventID != "audit-a" || recovered.Feature == nil || recovered.Feature.Operation != p.Feature.Operation {
				t.Fatal("generic terminal recovery lost original receipt", err)
			}
		}
	}
}

func TestAPIKeyVerificationNativeSchemaCannotUseGenericFallback(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		b, p := apiKeyVerificationPlanFixture(t, anonymous)
		p.APIKeyVerification = nil
		if _, err := encodeFeaturePlan(b, [32]byte{9}, p); err == nil {
			t.Fatal("declared native verification schema admitted without its closed plan")
		}
	}
}
