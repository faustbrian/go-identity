//go:build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Real SQL checkpoint/identity boundary; synthetic native participants do not
// claim production OTP cryptography, comparison or session interoperability.
func testMFAOTPPreparedDeclaration(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	var installed bool
	if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='identity' AND table_name='commands' AND column_name='preparation_profile')`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		if _, err := pool.Raw().Exec(ctx, preparationSchemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='identity' AND table_name='commands' AND column_name='preparation_declaration')`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		if _, err := pool.Raw().Exec(ctx, counterPreparationSchemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	b, p := mfaCompletionPlanFixture(t, "otp-verify")
	b.CommandID, _ = identity.NewCommandID()
	b.TenantID = "mfa-otp-declaration"
	base := identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{{Name: "transport.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "127.0.0.1"}}}}
	code, _ := auth.NewOneTimeCode("123456")
	cookie := auth.NewBearerCredential(strings.Repeat("A", 43))
	original, err := identity.NewFeatureOneTimeCodePreAuthCommand(base, code, cookie)
	if err != nil {
		t.Fatal(err)
	}
	mapped := base
	mapped.Fields = append(append([]identity.FeatureField(nil), base.Fields...), []identity.FeatureField{
		{Name: "otp.attempt-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("synthetic-native-custody")}},
		{Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
		{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "127.0.0.1"}},
		{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		{Name: "counter.subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "factor-user"}},
		{Name: "counter.capability", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}},
		{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Now().UTC().Truncate(time.Microsecond)}},
		{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 0, 0, 1}}},
	}...)
	prepared, err := identity.NewFeatureOneTimeCodePreAuthCommand(mapped, code, cookie)
	if err != nil {
		t.Fatal(err)
	}
	mapped, _ = prepared.Feature()
	owner := &mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}}, expected: prepared, proof: *p.Capability}, completion: *p.MFACompletion}
	registry, err := NewContributorRegistry([]Contributor{repo, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &magicLinkPreparationCounter{}, &otpReservationProbe{}, &capabilityExecutionProbe{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := &CommandQueryPolicy{Clock: finalProofClock{now}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	config := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: policy, AdmissionPolicy: policy}
	c, err := NewCoordinator(pool, registry, config)
	if err != nil {
		t.Fatal(err)
	}
	p.Contributors = registry.Descriptors()
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{9}}
	seed, err := securityMutationAudit(ctx, b, 0, 0, now, "committed", p.Audits[0].EventType, p.SubjectType, b.AnonymousFlowID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	p, err = c.PrepareMFAOTPFeaturePlanWithOriginal(original, prepared, p)
	if err != nil {
		t.Fatal(err)
	}
	// The test owner stops generation. Its earlier native mapped declaration
	// must already be committed; absent output must not permit a fresh attempt.
	result, err := c.ExecutePreparedMFAOTPFeature(ctx, original, prepared, p)
	if result.Outcome != identity.CommitOutcomeUnknown || !errors.As(err, new(identity.UnknownCommitError)) {
		t.Fatal("missing generation acknowledgement granted execution", result.Outcome, err)
	}
	var private bool
	if err := pool.Raw().QueryRow(ctx, `SELECT position(convert_to('127.0.0.1','UTF8') IN preparation_declaration)=0 FROM identity.commands WHERE tenant_id=$1 AND purpose=$2`, string(b.TenantID), b.OperationID).Scan(&private); err != nil || !private {
		t.Fatal("durable checkpoint exposed original raw network", err)
	}
	_, caller := queryInputs(b)
	got, plan, found, err := c.QueryMFAOTPPreparation(ctx, original, caller)
	if err != nil || !found || !reflect.DeepEqual(got, mapped) || plan.OTP == nil || *plan.OTP != *p.OTP {
		t.Fatal("pre-generation attempt checkpoint not restorable", found, err)
	}
	// Restart/current key rotation cannot replace old signed native metadata.
	config.CurrentFingerprintKeyVersion = 2
	config.RetainedFingerprintKeys[2] = [32]byte{2}
	c, err = NewCoordinator(pool, registry, config)
	if err != nil {
		t.Fatal(err)
	}
	got, plan, found, err = c.QueryMFAOTPPreparation(ctx, original, caller)
	if err != nil || !found || !reflect.DeepEqual(got, mapped) || *plan.OTP != *p.OTP {
		t.Fatal("restart changed original native attempt", found, err)
	}
	// Even an otherwise admitted new encrypted attempt cannot replace the
	// earlier declaration. This check happens before the busy/start disposition.
	changedMetadata := mapped
	changedMetadata.Fields = append([]identity.FeatureField(nil), mapped.Fields...)
	for i := range changedMetadata.Fields {
		if changedMetadata.Fields[i].Name == "otp.attempt-custody" {
			changedMetadata.Fields[i].Value.Bytes = []byte("different-synthetic-native-custody")
		}
	}
	changedPrepared, err := identity.NewFeatureOneTimeCodePreAuthCommand(changedMetadata, code, cookie)
	if err != nil {
		t.Fatal(err)
	}
	owner.expected = changedPrepared
	if _, err := c.ExecutePreparedMFAOTPFeature(ctx, original, changedPrepared, p); !errors.As(err, new(identity.ConflictError)) {
		t.Fatal("retry replaced native attempt before session generation", err)
	}
	owner.expected = prepared
	wrong, _ := auth.NewOneTimeCode("654321")
	changed, _ := identity.NewFeatureOneTimeCodePreAuthCommand(base, wrong, cookie)
	if _, _, found, err := c.QueryMFAOTPPreparation(ctx, changed, caller); !found || !errors.As(err, new(identity.ConflictError)) {
		t.Fatal("changed code obtained original attempt", found, err)
	}
	result, err = c.ExecutePreparedMFAOTPFeature(ctx, original, prepared, p)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("started-without-output was restarted", result.Outcome, err)
	}
	history, found, err := c.QueryMFAOTPCommand(ctx, original, caller)
	if err != nil || !found || history.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("pending original history required mutable factor source", found, err)
	}
}
