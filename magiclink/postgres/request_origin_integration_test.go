//go:build integration

package magiclinkpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Public request, real delivery/issuer custody, committed original journal,
// policy, decryption and whole-payload comparison are real. This bounded owner
// bridge fixture seeds the consumed-parent/child-origin tuple; native atomic
// production of that tuple has separate capability-owner integration coverage.
// No factor is verified and this is not a completed public MFA login journey.
func testMFAOriginalPrimaryReconstruction(t *testing.T, ctx context.Context, pool *database.Pool, service *RequestService, original capability.Proof, flow session.PreAuthTransaction, caller authorization.DecisionContext) {
	t.Helper()
	grant, requestID, replayVersion, _, err := service.issuer.ReadMagicLinkOrigin(ctx, pool, original)
	if err != nil {
		t.Fatal("original public request provenance unavailable", err)
	}
	parent := grant.Payload()
	primaryID, _ := identity.NewCommandID()
	childID, _ := identity.NewCommandID()
	f, _ := flow.Bindings()
	primaryAt := time.Now().UTC().Truncate(time.Second)
	childPayload := capability.Payload{Version: 1, Issuer: parent.Issuer, Audiences: []string{service.config().Issuer.Audience}, Subject: parent.Subject, Tenant: parent.Tenant, ID: string(childID), Resource: "mfa/continuations/" + string(childID), Operation: "identity.mfa.complete", MaxUses: 1, IssuedAt: primaryAt, NotBefore: primaryAt, ExpiresAt: parent.ExpiresAt, Caveats: map[string]string{"mfa.profile": "identity-mfa-continuation-v1", "mfa.scope": strings.Repeat("07", 32)}}
	if childPayload.ExpiresAt.Sub(primaryAt) > 5*time.Minute {
		childPayload.ExpiresAt = primaryAt.Add(5 * time.Minute)
	}
	op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	binding := identity.CommandBinding{CommandID: primaryID, TenantID: identity.TenantID(parent.Tenant), AnonymousFlowID: string(f.Binding.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: f.Binding.Intent.PolicyID, PolicyVersion: f.Binding.Intent.PolicyVersion, CorrelationID: string(primaryID)}
	prepared, err := service.issuer.PrepareMFAContinuation(ctx, binding, childPayload)
	if err != nil {
		t.Fatal("original fixture child signing failed", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		t.Fatal("original fixture child plan missing", err)
	}
	child := plan.Grants[0]
	var proof capability.Proof
	if err := prepared.TransferForDelivery(ctx, 0, func(_ context.Context, wire []byte) error {
		var err error
		proof, err = capability.ParseProof(string(wire), service.config().Issuer.Crypto.Limits)
		return err
	}); err != nil {
		t.Fatal("original fixture child custody unavailable", err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	canonical, err := capability.CanonicalPayload(childPayload, service.config().Issuer.Crypto.Limits)
	if err != nil {
		t.Fatal(err)
	}
	childDigest := sha256.Sum256(canonical)
	clear(canonical)
	originFingerprint := sha256.Sum256([]byte("owned-mfa-parent-reconstruction-fixture"))
	if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state='finalized',uses=1,command_id=$2,command_fingerprint=$3,generation=1 WHERE tenant_id=$1 AND purpose='identity.magic-link.consume' AND capability_id=$4`, parent.Tenant, string(primaryID), originFingerprint[:], parent.ID); err != nil {
		t.Fatal("owned consumed-parent fixture failed", err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.mfa.complete' AND capability_id=$2`, parent.Tenant, string(childID)); err != nil {
			t.Error("owned child cleanup failed", err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE public.capability_identity_one_use SET state='issued',uses=0,command_id=NULL,command_fingerprint=NULL,generation=NULL WHERE tenant_id=$1 AND purpose='identity.magic-link.consume' AND capability_id=$2`, parent.Tenant, parent.ID); err != nil {
			t.Error("owned parent restoration failed", err)
		}
	}()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) VALUES($1,'identity.mfa.complete',$2,$3,$4,$5,$6,1,$7,$8,1,$9,$10,$10,$11,$12,clock_timestamp())`, parent.Tenant, int64(child.ReplayKeyVersion), child.ReplayDigest[:], child.CapabilityID, child.ProofFingerprint[:], child.ExpiresAt, string(primaryID), originFingerprint[:], parent.Subject, childPayload.IssuedAt, service.config().Issuer.Crypto.Signer.KeyID(), childDigest[:]); err != nil {
		t.Fatal("owned child provenance fixture failed", err)
	}
	parentCustody, err := service.issuer.ReadMFAMagicLinkParent(ctx, pool, proof, parent.ID, grant.EnvelopeDigest(), parent.ExpiresAt)
	if err != nil {
		t.Fatal("original parent custody unavailable", err)
	}
	origin, err := parentCustody.Bindings()
	if err != nil || origin.ReplayKeyVersion != replayVersion {
		t.Fatal("original parent replay version changed", err)
	}
	var before, after string
	snapshot := func(dest *string) {
		t.Helper()
		if err := pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(c) ORDER BY purpose,capability_id)::text FROM public.capability_identity_one_use c WHERE tenant_id=$1`, parent.Tenant).Scan(dest); err != nil {
			t.Fatal("owned custody snapshot failed", err)
		}
	}
	snapshot(&before)
	for range 2 {
		result, err := service.ReadMFAMagicLinkPrimary(ctx, parentCustody, flow, primaryAt, caller)
		if err != nil {
			t.Fatal("public owner bridge failed", err)
		}
		meta, err := result.Authentication.Bindings()
		if err != nil || meta.CommandID != primaryID || meta.RequestCommandID != requestID || meta.CapabilityID != parent.ID || string(meta.IdentifierID) != parent.Caveats["magiclink.identifier"] || meta.IdentifierVersion != result.Recipient.Identifier.Version || meta.VerificationVersion != result.Recipient.Verification.Version || !meta.AuthenticatedAt.Equal(primaryAt) || !meta.ValidUntil.Equal(parent.ExpiresAt) || result.Recipient.User.ID != requestTestUser || result.Recipient.Query.CanonicalValue != "person@example.test" {
			t.Fatal("owner bridge changed original primary/recipient/times", err)
		}
	}
	snapshot(&after)
	if before != after {
		t.Fatal("original reconstruction consumed, renewed or changed custody")
	}
	foreignCaller := caller.Clone()
	foreignCaller.Request.Subject.ID = "foreign"
	if result, err := service.ReadMFAMagicLinkPrimary(ctx, parentCustody, flow, primaryAt, foreignCaller); err == nil || result != (MFAMagicLinkPrimary{}) {
		t.Fatal("foreign original-query actor obtained historical metadata")
	}
	if result, err := service.ReadMFAMagicLinkPrimary(ctx, parentCustody, flow, parent.ExpiresAt, caller); err == nil || result != (MFAMagicLinkPrimary{}) {
		t.Fatal("primary time renewed beyond original exclusive expiry")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if result, err := service.ReadMFAMagicLinkPrimary(cancelled, parentCustody, flow, primaryAt, caller); err == nil || result != (MFAMagicLinkPrimary{}) {
		t.Fatal("cancelled owner bridge retained metadata")
	}
	// Whole-payload digest comparison rejects a forged original browser nonce;
	// the retained original ciphertext does not authenticate a substituted flow.
	f.Binding.Intent.Nonce = sha256.Sum256([]byte(hex.EncodeToString(originFingerprint[:])))
	foreignFlow, err := session.NewPreAuthTransaction(f)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.ReadMFAMagicLinkPrimary(ctx, parentCustody, foreignFlow, primaryAt, caller); err == nil || result != (MFAMagicLinkPrimary{}) {
		t.Fatal("foreign browser scope authenticated historical primary")
	}
}
