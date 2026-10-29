package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func organizationAPIKeyPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := apiKeyVerificationPlanFixture(t, false)
	b.UserID, b.AnonymousFlowID, b.SchemaID = "", string(b.CommandID), "apikey-verify-organization-v1"
	p.Feature.Operation.SchemaID = b.SchemaID
	p.Feature.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	if err := b.ValidateFor(p.Feature.Operation); err != nil {
		t.Fatal("generic attempt scope cannot represent a real nonhuman key actor", err)
	}
	return b, p
}

func TestOrganizationAPIKeyVerificationRetainsOriginalPreparationAndRecovery(t *testing.T) {
	b, declaration := organizationAPIKeyPlanFixture(t)
	c, command, declaration, native := apiKeyVerificationBindingRuntimeFixture(t, b, declaration)
	prepared, err := c.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		t.Fatal("nonhuman key preparation lost native ownership", err)
	}
	claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
	admitted, err := c.registry.admitFeaturePlan(b, fingerprint, prepared)
	if err != nil || admitted.apiKeyVerification == nil || admitted.binding != b {
		t.Fatal("nonhuman key preparation lost original scope or comparison phase", err)
	}
	query, caller := queryInputs(b)
	policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.admissionPolicy, c.queryPolicy = policy, policy
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		return commandObservation{}, pgx.ErrNoRows
	}
	if out, fp, err := c.ObserveAPIKeyVerificationCommand(t.Context(), command, caller); err != nil || !out.Absent || fp != fingerprint {
		t.Fatal("organization attempt cannot observe genuine prospective absence", err)
	}
	now, state, profile := time.Now().UTC().Truncate(time.Microsecond), "pending", int16(2)
	until := now.Add(-time.Minute)
	observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, state: &state, until: &until, now: now, fingerprint: bytes.Clone(fingerprint[:]), fingerprintKeyVersion: int64(c.keys.current), preparationProfile: &profile}
	var unavailable identity.UnavailableError
	if err := readObservedCounterPreparation(t.Context(), lostPreparationSnapshotReader{}, nil, &observed); !errors.As(err, &unavailable) {
		t.Fatal("organization preparation snapshot loss was not treated as uncertainty", err)
	}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	c.keys.current, c.keys.retained[2] = 2, [32]byte{28}
	for _, attached := range []bool{false, true} {
		if attached {
			observed.plan, err = encodeFeaturePlan(b, fingerprint, prepared)
			if err != nil {
				t.Fatal(err)
			}
		}
		if out, fp, err := c.ObserveAPIKeyVerificationCommand(t.Context(), command, caller); err != nil || out.Record.Outcome != identity.CommitOutcomeInProgress || fp != fingerprint {
			t.Fatal("organization attempt renewed or replaced original commitment", attached, err)
		}
		if !attached {
			out, err := c.RecoverAPIKeyVerificationCommand(t.Context(), query, fingerprint, caller)
			if err != nil || out.Outcome != identity.CommitOutcomeInProgress || out.Binding != b || native.verificationCalls != 0 {
				t.Fatal("expired organization preparation reran authentication or fabricated noncommit", err)
			}
		}
	}
	declaration.APIKeyVerification = nil
	if _, err := FeaturePlanDigest(b, fingerprint, declaration); err == nil {
		t.Fatal("organization verification entered generic mutation fallback")
	}
}

func TestOrganizationAPIKeyVerificationRetainsKnownKeyWithoutHuman(t *testing.T) {
	b, declaration := organizationAPIKeyPlanFixture(t)
	fingerprint := [32]byte{9}
	wire, err := encodeFeaturePlan(b, fingerprint, declaration)
	if err != nil {
		t.Fatal("organization-owned known key was classified as an unknown credential", err)
	}
	got, err := decodeFeaturePlan(b, fingerprint, wire)
	declaration.Digest = sha256.Sum256(wire)
	if err != nil || !reflect.DeepEqual(got, declaration) || got.APIKeyVerification.KeyVersion != 7 || got.Feature.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || b.UserID != "" || b.ActorKind != authorization.SubjectAPIKey {
		t.Fatal("retained organization-key attempt lost exact actor/schema/version", err)
	}
	changed := fingerprint
	changed[0]++
	if decoded, err := decodeFeaturePlan(b, changed, wire); err == nil || !reflect.DeepEqual(decoded, CommandPlan{}) {
		t.Fatal("organization key retained a plan under another original fingerprint")
	}
}

func TestOrganizationAPIKeyVerificationUsesTypedNativePhase(t *testing.T) {
	for _, outcome := range []APIKeyVerificationOutcome{{}, {Authenticated: true}, {PermissionsChanged: true}, {Authenticated: true, PermissionsChanged: true}} {
		b, p := organizationAPIKeyPlanFixture(t)
		c, command, p, native := apiKeyVerificationBindingRuntimeFixture(t, b, p)
		prepared, err := c.PrepareCommandPlan(b, command, p)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := c.registry.admitFeaturePlan(b, claimFingerprint(c.keys.retained[c.keys.current], claim.canonical), prepared)
		if err != nil {
			t.Fatal(err)
		}
		reservation := &reservationState{plan: admitted, request: claim, journal: journalReservation{generation: 1}}
		w := Work{state: &workState{ctx: t.Context(), binding: b, generation: 1, registry: c.registry.state}}
		if err := admitted.bindWork(w); err != nil {
			t.Fatal(err)
		}
		w.state.execution = &domainExecution{coordinator: c, reservation: reservation}
		native.outcome = outcome
		receipt, err := invokeFeature(native, t.Context(), w, command)
		if err != nil || receipt != (identity.FeatureReceipt{Operation: p.Feature.Operation}) || native.verificationCalls != 1 || native.genericCalls != 0 || w.state.apiKeyVerification == nil || *w.state.apiKeyVerification != outcome {
			t.Fatal("organization actor bypassed typed comparison or changed native outcome", err)
		}
		if _, _, _, err := w.FeatureCommandIdentity(native); err == nil {
			t.Fatal("organization comparison retained expired invocation authority")
		}
	}
}

func TestOrganizationAPIKeyVerificationAuditsActualKeyNotCreatorOrFlow(t *testing.T) {
	for _, narrowed := range []bool{false, true} {
		b, declaration := organizationAPIKeyPlanFixture(t)
		plan := &admittedKernelPlan{binding: b, feature: declaration.Feature, subjectType: declaration.SubjectType, lifecycle: declaration.Lifecycle, audits: declaration.Audits, apiKeyVerification: declaration.APIKeyVerification}
		got, err := buildAPIKeyVerificationEffects(t.Context(), plan, APIKeyVerificationOutcome{Authenticated: true, PermissionsChanged: narrowed}, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			t.Fatal("known organization key could not commit a nonhuman authentication outcome", err)
		}
		expectedCount := 1
		if narrowed {
			expectedCount = 2
		}
		if len(got.audits) != expectedCount || got.audits[0].Outcome() != audit.OutcomeSucceeded || got.audits[0].Subject().Type() != "api_key" || got.audits[0].Subject().ID() != string(b.ActorID) || got.audits[0].Actor().Kind() == audit.ActorHuman {
			t.Fatal("organization-key authentication fabricated a creator or audited an unknown flow")
		}
		if narrowed {
			if got.lifecycle == nil || got.lifecycle.BeforeVersion != 7 || got.lifecycle.AfterVersion != 8 || got.audits[1].Subject().ID() != string(b.ActorID) {
				t.Fatal("organization-key narrowing lost the exact key mutation")
			}
		} else if got.lifecycle != nil {
			t.Fatal("ordinary organization-key verification invented a mutation")
		}
	}
}

func TestOrganizationAPIKeyVerificationRejectsInventedOwnerAuthority(t *testing.T) {
	for _, variant := range []string{"creator-user", "human-actor", "service-actor", "foreign-flow", "unknown-schema", "zero-key-version", "exhausted-key-version"} {
		t.Run(variant, func(t *testing.T) {
			b, p := organizationAPIKeyPlanFixture(t)
			switch variant {
			case "creator-user":
				b.UserID = "creator"
			case "human-actor":
				b.ActorKind = authorization.SubjectUser
			case "service-actor":
				b.ActorKind = authorization.SubjectServiceAccount
			case "foreign-flow":
				b.AnonymousFlowID = "another-attempt"
			case "unknown-schema":
				b.SchemaID = "apikey-verify-unknown-v1"
				p.Feature.Operation.SchemaID = b.SchemaID
			case "zero-key-version":
				p.APIKeyVerification.KeyVersion = 0
			case "exhausted-key-version":
				p.APIKeyVerification.KeyVersion = ^uint64(0)
			}
			if _, err := FeaturePlanDigest(b, [32]byte{9}, p); err == nil {
				t.Fatal("ambiguous nonhuman verification scope acquired authority")
			}
		})
	}
}
