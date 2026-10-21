//go:build integration

package anonymouspostgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	capability "github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func anonymousUpgradeConfiguration(t *testing.T, f publicAnonymousFixture, target anonymousUpgradeTarget, afterRetention ...func(context.Context, identity.RetentionPolicyInput) error) anonymouspg.UpgradeConfig {
	t.Helper()
	ctx := f.ctx
	kernelBase := kernel.AnonymousDisposalMigrationSource{Base: kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: f.config.Profile.GlobalAuthorityID, TenantIDs: []identity.TenantID{"tenant-a", "AAAAAAAAAAAAAAAAAAAAAQ"}}, Version: 16}
	for n, source := range []migrations.Source{
		kernel.AnonymousUpgradeDisposalMigrationSource{Base: kernelBase, Version: 70},
		sessionpg.AnonymousUpgradeMigrationSource{AnonymousSignin: sessionpg.AnonymousSigninMigrationSource{Schema: "session_store", Version: 23, Predecessor: sessionpg.AnonymousAfterBaseIssuance}, Version: 71},
		anonymouspg.UpgradeMigrationSource{Schema: "anonymous_store", Version: 72},
		riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "anonymous_upgrade_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4},
	} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if n == 0 && step.Version() < 70 {
				continue
			}
			if _, err := f.pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("real native upgrade owner history", err)
			}
		}
	}
	// Install the actual capability owner's history. No issued row is seeded:
	// the public native workflow must durably issue and then consume its grant.
	files := capabilitypg.Migrations()
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal("actual capability history", err)
		}
	}
	retention, err := identity.NewPolicyEvaluator(identity.PolicySet{Authorize: anonymousPolicy{}, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
		return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
	}, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
	}, DecideRetention: func(_ context.Context, in identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		if in.OperationID != "identity.anonymous.upgrade" || in.ActorID != identity.ActorID(upgradeTargetID) || in.SubjectID == upgradeTargetID || in.Resource.Kind != "anonymous" || in.Resource.ID != string(in.SubjectID) {
			return identity.RetentionPolicyDecision{}, identity.ForbiddenError{}
		}
		if len(afterRetention) != 0 {
			if err := afterRetention[0](ctx, in); err != nil {
				return identity.RetentionPolicyDecision{}, err
			}
		}
		d := identity.RetentionAllow
		if in.LegalHold {
			d = identity.RetentionBlockLegalHold
		}
		return identity.RetentionPolicyDecision{Disposition: d, PolicyID: "anonymous-upgrade-retention", PolicyVersion: 1, Reasons: []identity.PolicyReason{"guest-upgrade"}}, nil
	}}, identity.PolicyEvaluatorConfig{PolicyID: "anonymous-upgrade-retention", PolicyVersion: 1, Reasons: []identity.PolicyReason{"guest-upgrade"}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Clock: f.config.Issuer.Clock, MaximumDuration: 3 * time.Second, ClockUncertainty: time.Millisecond, Audience: f.config.Profile.Audience, LookupKeys: []session.DigestKey{f.lookupKey}}
	guest := anonymouspg.DeletionConfig{Repository: f.config.Repository, Sessions: f.config.Sessions, Profile: f.config.Profile, Validation: validation, CSRFKeys: []session.CSRFKey{f.csrfKey}, Origins: f.config.Origins, Reasons: []string{"guest-upgrade"}, ConfigurationID: "anonymous-upgrade-v1", PolicyID: "anonymous-upgrade", Retention: retention, RetentionPolicyVersion: 1, RequestKeys: f.config.RequestKeys, Coordinator: f.config.Coordinator, IntentKey: [32]byte{90}, ActiveEnvelopeKeyID: f.config.ActiveEnvelopeKeyID, Risk: riskpg.Config{Schema: "anonymous_upgrade_risk", PolicyVersion: 1, EvidenceKeys: []risk.EvidenceKey{f.evidence}, EnvelopeKeys: map[string][]byte{"risk-input": bytes.Repeat([]byte{92}, 32)}, CurrentEnvelopeKey: "risk-input", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: f.riskPolicy, Keys: []risk.CounterDigestKey{f.counterKey}}}}
	signing := bytes.Repeat([]byte{93}, 32)
	signer, err := capability.NewHMACSHA256Signer("upgrade-signing", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "anonymous-upgrade", ID: "upgrade-signing", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	issued := capabilitypg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "anonymous-upgrade", Signer: signer, Resolver: keys, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: upgradeProofAudience, CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {94}}, PreparationTimeout: time.Second}
	checkpoint := capabilitypg.IssuancePreparationConfig{Deployment: "anonymous-native-test", ActiveEnvelopeKey: "upgrade-checkpoint", EnvelopeKeys: map[string][]byte{"upgrade-checkpoint": bytes.Repeat([]byte{95}, 32)}, VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "upgrade-signing", HMAC: signing}}, Clock: time.Now}
	return anonymouspg.UpgradeConfig{Guest: guest, Primary: target.primary, Target: sessionpg.SessionServiceConfig{Repository: f.config.Sessions, Profile: target.profile, Validation: validation}, TargetCSRFKeys: []session.CSRFKey{f.csrfKey}, ProofAudience: upgradeProofAudience, Issuer: f.config.Issuer, CSRF: f.csrfKey, Capability: issued, CapabilityPreparation: checkpoint}
}

func TestNativePublicAnonymousUpgradePreservesPermanentTargetAndRevokesAllGuests(t *testing.T) {
	f := newPublicAnonymousFixture(t)
	signin := f.fresh()
	guestResult, err := f.service.Signin(f.ctx, signin)
	if err != nil {
		t.Fatal(err)
	}
	guest, _ := guestResult.Session.Session.Bindings()
	seedAnonymousDisposalSiblings(t, f, guestResult.Session.Session)
	target := newAnonymousUpgradeTarget(t, f, guest.Remember)
	proof := target.verify(t, f)
	config := anonymousUpgradeConfiguration(t, f, target)
	service, err := anonymouspg.NewUpgradeService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal("native upgrade composition", err)
	}
	repository, err := anonymouspg.NewRepository(f.pool, f.config.Repository)
	if err != nil {
		t.Fatal(err)
	}
	source, err := repository.Read(f.ctx, anonymous.SubjectQuery{TenantID: guest.TenantID, UserID: guest.UserID})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, guestResult.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("native-anonymous-upgrade-original"))
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(guest.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(upgradeTargetID)}, Action: "identity.anonymous.upgrade", Resource: authorization.Resource{Type: "anonymous", ID: authorization.ResourceID(guest.UserID)}}}
	r := anonymous.UpgradeRequest{TenantID: guest.TenantID, TargetSession: target.bearer, TargetProof: proof, TargetCSRF: target.csrf, Guest: credential, GuestCSRF: guestResult.CSRFToken, Plan: anonymous.MergePlan{Source: source, Target: identity.SubjectID(upgradeTargetID)}, Remember: guest.Remember, Caller: caller, Origin: signin.Origin, Network: signin.Network, Device: signin.Device, IdempotencyKey: key}
	var upgrader anonymous.Upgrader = service
	out, err := upgrader.Upgrade(f.ctx, r)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Preparation.CommandID == "" || out.Recovery.CommandID == "" || out.Preparation.CommandID == out.Recovery.CommandID || out.Session.Token == (session.Token{}) || out.CSRFToken == (session.CSRFToken{}) {
		for _, q := range []identity.RecoveryQuery{out.Preparation, out.Recovery} {
			id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
			var state string
			if e := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, id).Scan(&state); e == nil {
				t.Log("original upgrade phase state", q.RecordID == "", state)
			}
		}
		t.Fatal("actual native upgrade failed to commit/deliver", err, out.Outcome)
	}
	permanent, err := out.Session.Session.Bindings()
	original, _ := target.record.Bindings()
	if err != nil || permanent.UserID != upgradeTargetID || permanent.UserID == guest.UserID || permanent.Remember != guest.Remember || permanent.Authentication != original.Authentication || permanent.SessionID == original.SessionID || permanent.FamilyID == original.FamilyID {
		t.Fatal("upgrade lost target/remember/authentication provenance", err)
	}
	var status string
	var version string
	var guestState, sessions, families, targetSessions, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT u.status,u.version::text,(SELECT state FROM anonymous_store.subjects WHERE tenant_id=$1 AND user_id=$3),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$3 AND state='revoked'),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND user_id=$3 AND state='revoked'),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND consumed_command_id IS NOT NULL) FROM identity.users u WHERE u.tenant_id=$1 AND u.user_id=$2`, string(guest.TenantID), string(upgradeTargetID), string(guest.UserID)).Scan(&status, &version, &guestState, &sessions, &families, &targetSessions, &consumed); err != nil || status != "active" || version != "1" || guestState != int(anonymous.StateUpgraded) || sessions != 18 || families != 19 || targetSessions != 2 || consumed != 1 {
		t.Fatal("upgrade owners disagree or permanent target changed", err, status, version, guestState, sessions, families, targetSessions, consumed)
	}
	var finalized, uses int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),coalesce(sum(uses),0) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.anonymous.upgrade' AND subject_id=$2 AND state='finalized'`, string(r.TenantID), string(upgradeTargetID)).Scan(&finalized, &uses); err != nil || finalized != 1 || uses != 1 {
		t.Fatal("upgrade omitted actual one-use finalization", err, finalized, uses)
	}
	reader, err := sessionpg.NewSessionService(f.pool, config.Target)
	if err != nil {
		t.Fatal(err)
	}
	newCredential, err := session.NewCredential(session.CredentialCookie, out.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(f.ctx, session.GetRequest{TenantID: r.TenantID, Credential: newCredential})
	if err != nil || !read.Authenticated {
		t.Fatal("new permanent session cannot authenticate", err)
	}
	fresh, err := anonymouspg.NewUpgradeService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := fresh.RecoverUpgrade(f.ctx, anonymous.UpgradeRecoveryRequest{Preparation: out.Preparation, Recovery: out.Recovery, TargetSession: r.TargetSession, TargetCSRF: r.TargetCSRF, Guest: r.Guest, GuestCSRF: r.GuestCSRF, Origin: r.Origin, Network: r.Network, Device: r.Device})
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("original two-command recovery lost outcome or redelivered", err)
	}
	replayed, err := fresh.Upgrade(f.ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Recovery != out.Recovery || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("terminal upgrade replay reexecuted or disclosed credential", err)
	}
}
