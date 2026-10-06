//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// Real owned risk participant through the sole coordinator, with independent
// primary SQL assertions. Effect seams are not production adapter interop.
func testNativeCaptchaReplay(t *testing.T, ctx context.Context, pool *database.Pool) {
	var at time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	_, key, profile := captchaConfiguredFixture(t, captchaFlowFixture(), at.UTC())
	custody, err := risk.NewCaptchaEvidenceCustody(profile)
	if err != nil {
		t.Fatal(err)
	}
	shortProfile := profile
	shortProfile.Lifetime = 3 * time.Second
	shortCustody, err := risk.NewCaptchaEvidenceCustody(shortProfile)
	if err != nil {
		t.Fatal(err)
	}
	_, _, disjointProfile := captchaConfiguredFixture(t, captchaFlowFixture(), at.UTC(), 2)
	disjointCustody, err := risk.NewCaptchaEvidenceCustody(disjointProfile)
	if err != nil {
		t.Fatal(err)
	}
	replacementKey, err := risk.NewCaptchaReplayKey(1, bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, _, replacementProfile := captchaConfiguredKeyFixture(t, captchaFlowFixture(), at.UTC(), []risk.CaptchaReplayKey{replacementKey})
	replacementCustody, err := risk.NewCaptchaEvidenceCustody(replacementProfile)
	if err != nil {
		t.Fatal(err)
	}
	_, _, overlapFirst := captchaConfiguredFixture(t, captchaFlowFixture(), at.UTC(), 3, 1)
	_, _, overlapSecond := captchaConfiguredFixture(t, captchaFlowFixture(), at.UTC(), 2, 1)
	overlapCustodyFirst, err := risk.NewCaptchaEvidenceCustody(overlapFirst)
	if err != nil {
		t.Fatal(err)
	}
	overlapCustodySecond, err := risk.NewCaptchaEvidenceCustody(overlapSecond)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", CaptchaCustody: []risk.CaptchaEvidenceCustody{custody, shortCustody, disjointCustody, replacementCustody, overlapCustodyFirst, overlapCustodySecond}})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{domain, &issuanceAudit{}, &issuanceOutbox{}, repo})
	if err != nil {
		t.Fatal(err)
	}
	c, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceQueryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	flowInput := captchaFlowFixture()
	prepare := func(token []byte) (identity.CommandBinding, identity.Command, identitypostgres.CommandPlan, risk.CaptchaEvidenceIssue) {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		capture := &captchaCapture{}
		cfg := profile
		cfg.Executor = capture
		issuer, err := risk.NewCaptchaEvidenceIssuer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		flow, err := risk.NewFlowContext(flowInput)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := issuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: string(id), Flow: flow}, token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := issuer.Issue(ctx, intent, token); err != nil {
			t.Fatal(err)
		}
		issue := capture.issue
		cmd, err := MapCaptchaIssue(issue, captchaCommandBinding(issue.Prepared()))
		if err != nil {
			t.Fatal(err)
		}
		spec, _ := cmd.Feature()
		b := spec.Binding
		builder, err := audit.NewBuilder(audit.BuilderConfig{})
		if err != nil {
			t.Fatal(err)
		}
		seed, err := builder.Build(audit.RecordInput{OccurredAt: at.UTC(), Action: "identity.captcha.verify", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "captcha_evidence", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "captcha_evidence", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := identitypostgres.FeatureAuditBindingDigest(b, spec.Operation, "captcha_evidence", seed)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := c.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "captcha_evidence", CaptchaReplayReservation: true, Feature: &identitypostgres.FeatureRegistration{Contributor: repo.Descriptor(), Operation: spec.Operation}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "identity.captcha.issued.v1", AfterVersion: 1}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.captcha.verify", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native plan", err)
		}
		return b, cmd, plan, issue
	}
	for _, rollback := range []bool{false, true} {
		name, token := "committed", []byte("synthetic-committed-captcha-token")
		if rollback {
			name, token = "rolled-back", []byte("synthetic-rolled-back-captcha-token")
		}
		t.Run(name, func(t *testing.T) {
			b, cmd, plan, issue := prepare(token)
			r, result, err := c.ReserveCommand(ctx, b, cmd, plan)
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("native replay reservation", err)
			}
			w, err := c.Begin(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, err = c.ApplyFeature(ctx, w, cmd)
			if err != nil {
				t.Fatal("native evidence apply", err)
			}
			if rollback {
				if result, err = c.Abort(w, identity.UnavailableError{}); result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("rollback committed evidence", err)
				}
			} else if result, err = c.Commit(w, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("native evidence commit", err)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var winners, aliases, versions, issued, successes, messages int
			err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.captcha_replay_winners WHERE command_id=$1),(SELECT count(*) FROM risk_store.captcha_replay_aliases WHERE command_id=$1),(SELECT count(*) FROM risk_store.captcha_replay_alias_versions v JOIN risk_store.captcha_replay_aliases a USING(tenant_id,provider,site,api_profile,configuration_version,fingerprint) WHERE a.command_id=$1),(SELECT count(*) FROM risk_store.captcha_issued_evidence WHERE command_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id=$2 AND record->>'outcome'='1'),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$2)`, id, string(b.CommandID)).Scan(&winners, &aliases, &versions, &issued, &successes, &messages)
			want := 1
			if rollback {
				want = 0
			}
			if err != nil || winners != 1 || aliases != 1 || versions != 1 || issued != want || successes != want || messages != want {
				t.Fatalf("native atomicity %d/%d/%d/%d/%d/%d: %v", winners, aliases, versions, issued, successes, messages, err)
			}
			if !rollback {
				var issuedAt, expiresAt time.Time
				var envelope []byte
				if err := pool.Raw().QueryRow(ctx, `SELECT issued_at,expires_at,response_envelope FROM risk_store.captcha_issued_evidence WHERE command_id=$1`, id).Scan(&issuedAt, &expiresAt, &envelope); err != nil {
					t.Fatal(err)
				}
				original, err := issue.Materialize(issuedAt.UTC())
				if err != nil || !expiresAt.Equal(original.ExpiresAt) || bytes.Contains(envelope, []byte(original.Reference.Reveal())) {
					t.Fatal("original custody was renewed or stored plaintext", err)
				}
				metadata := original
				metadata.Reference = risk.CaptchaEvidenceRef{}
				if restored, err := repo.cipher.openCaptcha(ctx, b, metadata, envelope); err != nil || restored != original {
					t.Fatal("original encrypted response not conserved", err)
				}
				clear(envelope)
			}
			// Different commands cannot reissue even after a proved domain rollback.
			other, otherCommand, otherPlan, _ := prepare(token)
			if _, result, err := c.ReserveCommand(ctx, other, otherCommand, otherPlan); err == nil && result.Outcome == identity.CommitOutcomeInProgress {
				t.Fatal("different command reacquired provider token")
			}
		})
	}
	for _, test := range []string{"native-consuming", "native-consuming-expiry", "native-domain-success", "native-domain-rollback", "native-domain-expiry", "native-domain-tamper", "native-domain-recover", "native-domain-recover-expired", "native-domain-recover-unknown", "native-domain-recover-divergent", "native-domain-recover-profile-removed", "native-domain-recover-signature", "native-domain-recover-revoked"} {
		t.Run(test, func(t *testing.T) {
			originalProfile := profile
			defer func() { profile = originalProfile }()
			if test == "native-consuming-expiry" || test == "native-domain-expiry" || test == "native-domain-recover-expired" {
				var current time.Time
				if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&current); err != nil {
					t.Fatal(err)
				}
				_, _, profile = captchaConfiguredFixture(t, captchaFlowFixture(), current.UTC())
				profile.Lifetime = shortProfile.Lifetime
				verify := profile.Verify
				profile.Verify = func(ctx context.Context, request risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
					observation, err := verify(ctx, request)
					observation.ExpiresAt = observation.ObservedAt.Add(shortProfile.Lifetime)
					return observation, err
				}
			}
			b, cmd, plan, issue := prepare([]byte("synthetic-" + test + "-captcha-token"))
			reservation, _, err := c.ReserveCommand(ctx, b, cmd, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(work, identity.UnavailableError{})
			result, err := c.ApplyFeature(ctx, work, cmd)
			if err != nil {
				t.Fatal(err)
			}
			if result, err = c.Commit(work, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("source issuance did not commit", err)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var issuedAt time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT issued_at FROM risk_store.captcha_issued_evidence WHERE command_id=$1`, id).Scan(&issuedAt); err != nil {
				t.Fatal(err)
			}
			record, err := issue.Materialize(issuedAt.UTC())
			if err != nil {
				t.Fatal(err)
			}
			testNativeCaptchaUse(t, ctx, pool, repo, profile, issue, record, test)
		})
	}
	t.Run("exact-generation-takeover", func(t *testing.T) {
		b, cmd, plan, _ := prepare([]byte("synthetic-takeover-captcha-token"))
		old, result, err := c.ReserveCommand(ctx, b, cmd, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("initial owner", err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		// An isolated primary fixture expires only the command lease, never the
		// evidence or replay winner. The real coordinator performs the transfer.
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		current, result, err := c.ReserveCommand(ctx, b, cmd, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("native owner takeover", err)
		}
		var generation string
		if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM risk_store.captcha_replay_winners WHERE command_id=$1`, id).Scan(&generation); err != nil || generation != "2" {
			t.Fatal("replay owner not conserved at exact generation", err)
		}
		if stale, err := c.Begin(ctx, old); err == nil {
			c.Abort(stale, identity.UnavailableError{})
			t.Fatal("stale owner entered domain")
		}
		w, err := c.Begin(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Abort(w, identity.UnavailableError{})
		result, err = c.ApplyFeature(ctx, w, cmd)
		if err != nil {
			t.Fatal("current-generation domain", err)
		}
		if result, err = c.Commit(w, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("takeover commit", err)
		}
	})
	t.Run("referenced-replay-key-cannot-be-omitted", func(t *testing.T) {
		// Both profiles are selected. Dropping a referenced key cannot make an
		// already-owned provider token fresh merely by changing its fingerprint.
		original := profile
		profile = disjointProfile
		defer func() { profile = original }()
		b, cmd, plan, _ := prepare([]byte("synthetic-committed-captcha-token"))
		if _, result, err := c.ReserveCommand(ctx, b, cmd, plan); err == nil && result.Outcome == identity.CommitOutcomeInProgress {
			t.Fatal("omitted retained replay key admitted a second winner")
		}
	})
	t.Run("fresh-disjoint-key-configurations-have-one-winner", func(t *testing.T) {
		original := profile
		defer func() { profile = original; flowInput = captchaFlowFixture() }()
		// Separate command claims and SQL connections contend on a previously
		// empty provider scope; no alias overlaps across these configurations.
		for attempt := 0; attempt < 8; attempt++ {
			flowInput.Tenant = "race-tenant-" + strconv.Itoa(attempt)
			profile = original
			b1, cmd1, plan1, _ := prepare([]byte("synthetic-disjoint-race-token"))
			profile = disjointProfile
			b2, cmd2, plan2, _ := prepare([]byte("synthetic-disjoint-race-token"))
			start := make(chan struct{})
			var wg sync.WaitGroup
			outcomes := make(chan bool, 2)
			reserve := func(b identity.CommandBinding, cmd identity.Command, plan identitypostgres.CommandPlan) {
				defer wg.Done()
				<-start
				_, result, err := c.ReserveCommand(ctx, b, cmd, plan)
				outcomes <- err == nil && result.Outcome == identity.CommitOutcomeInProgress
			}
			wg.Add(2)
			go reserve(b1, cmd1, plan1)
			go reserve(b2, cmd2, plan2)
			close(start)
			wg.Wait()
			close(outcomes)
			admitted := 0
			for ok := range outcomes {
				if ok {
					admitted++
				}
			}
			var winners, keys int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.captcha_replay_winners WHERE tenant_id=$1),(SELECT count(*) FROM risk_store.captcha_replay_scope_keys WHERE tenant_id=$1)`, flowInput.Tenant).Scan(&winners, &keys); err != nil || admitted != 1 || winners != 1 || keys != 1 {
				t.Fatalf("disjoint scope produced %d admitted/%d winners/%d retained keys: %v", admitted, winners, keys, err)
			}
		}
	})
	t.Run("same-version-secret-replacement-denied", func(t *testing.T) {
		original := profile
		token := []byte("synthetic-same-version-secret-token")
		initial, initialCommand, initialPlan, _ := prepare(token)
		if _, result, err := c.ReserveCommand(ctx, initial, initialCommand, initialPlan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("initial replay key owner", err)
		}
		profile = replacementProfile
		defer func() { profile = original }()
		b, cmd, plan, _ := prepare(token)
		if _, result, err := c.ReserveCommand(ctx, b, cmd, plan); err == nil && result.Outcome == identity.CommitOutcomeInProgress {
			t.Fatal("same-version replacement secret admitted another winner")
		}
	})
	t.Run("non-newest-key-overlap-has-one-winner", func(t *testing.T) {
		original := profile
		defer func() { profile = original; flowInput = captchaFlowFixture() }()
		flowInput.Tenant = "overlap-tenant"
		profile = overlapFirst
		b1, cmd1, plan1, firstIssue := prepare([]byte("synthetic-overlapping-key-token"))
		profile = overlapSecond
		b2, cmd2, plan2, secondIssue := prepare([]byte("synthetic-overlapping-key-token"))
		first, second := firstIssue.Prepared().Binding.Replay.Keys, secondIssue.Prepared().Binding.Replay.Keys
		if first[1].Version != 1 || second[1].Version != 1 || first[1].Fingerprint != second[1].Fingerprint || first[0].Fingerprint == second[0].Fingerprint {
			t.Fatal("fixture does not overlap only on non-newest alias")
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		outcomes := make(chan bool, 2)
		reserve := func(b identity.CommandBinding, cmd identity.Command, plan identitypostgres.CommandPlan) {
			defer wg.Done()
			<-start
			_, result, err := c.ReserveCommand(ctx, b, cmd, plan)
			outcomes <- err == nil && result.Outcome == identity.CommitOutcomeInProgress
		}
		wg.Add(2)
		go reserve(b1, cmd1, plan1)
		go reserve(b2, cmd2, plan2)
		close(start)
		wg.Wait()
		close(outcomes)
		admitted := 0
		for ok := range outcomes {
			if ok {
				admitted++
			}
		}
		var winners, aliases, versions int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.captcha_replay_winners WHERE tenant_id=$1),(SELECT count(*) FROM risk_store.captcha_replay_aliases WHERE tenant_id=$1),(SELECT count(*) FROM risk_store.captcha_replay_alias_versions WHERE tenant_id=$1)`, flowInput.Tenant).Scan(&winners, &aliases, &versions); err != nil || admitted != 1 || winners != 1 || aliases != 2 || versions != 2 {
			t.Fatalf("non-newest overlap produced %d admitted/%d winners/%d aliases/%d versions: %v", admitted, winners, aliases, versions, err)
		}
	})
	t.Run("retained-original-owner-takeover-after-key-addition", func(t *testing.T) {
		original := profile
		defer func() { profile = original; flowInput = captchaFlowFixture() }()
		flowInput.Tenant = "rotation-takeover-tenant"
		b, cmd, plan, issue := prepare([]byte("synthetic-original-pending-token"))
		if _, result, err := c.ReserveCommand(ctx, b, cmd, plan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("original reservation", err)
		}
		profile = overlapSecond
		newBinding, newCommand, newPlan, _ := prepare([]byte("synthetic-new-key-other-token"))
		if _, result, err := c.ReserveCommand(ctx, newBinding, newCommand, newPlan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("retained key addition", err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		current, result, err := c.ReserveCommand(ctx, b, cmd, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("retained original takeover failed", err)
		}
		w, err := c.Begin(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Abort(w, identity.UnavailableError{})
		result, err = c.ApplyFeature(ctx, w, cmd)
		if err != nil {
			t.Fatal("original rotated-key domain", err)
		}
		if result, err = c.Commit(w, result); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original rotated-key commit", err)
		}
		var aliases int
		var expiresAt time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.captcha_replay_aliases WHERE command_id=$1),expires_at FROM risk_store.captcha_issued_evidence WHERE command_id=$1`, id).Scan(&aliases, &expiresAt); err != nil || aliases != 1 || !expiresAt.Equal(issue.Prepared().ExpiresAt) {
			t.Fatal("takeover expanded original aliases or validity", err)
		}
	})
	t.Run("expired-pending-absence-reconciles-original-generation", func(t *testing.T) {
		b, cmd, plan, _ := prepare([]byte("synthetic-primary-noncommit-recovery-token"))
		if _, result, err := c.ReserveCommand(ctx, b, cmd, plan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("pending reservation", err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
		result, err := c.RecoverFeatureCommand(ctx, q, caller)
		if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("exact absent participant did not reconcile noncommit", err)
		}
		var winners, evidence int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.captcha_replay_winners WHERE command_id=$1),(SELECT count(*) FROM risk_store.captcha_issued_evidence WHERE command_id=$1)`, id).Scan(&winners, &evidence); err != nil || winners != 1 || evidence != 0 {
			t.Fatal("reconciliation released replay ownership or created evidence", err)
		}
		if status, err := repo.classifyCaptchaRecovery(ctx, b, nil); err != nil || status != identitypostgres.RecoveryNotCommitted {
			t.Fatal("authenticated-owner absence classification", err)
		}
	})
	for _, mode := range []string{"authentic-positive", "corrupt-response", "foreign-binding", "foreign-generation"} {
		t.Run("recovery-retains-unresolved-"+mode, func(t *testing.T) {
			b, cmd, plan, issue := prepare([]byte("synthetic-unresolved-" + mode))
			if _, result, err := c.ReserveCommand(ctx, b, cmd, plan); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("pending reservation", err)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if mode == "foreign-generation" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE risk_store.captcha_replay_winners SET generation=99 WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
			} else {
				// Deliberately inconsistent retained history: a participant effect
				// exists without the other effects or a terminal command receipt.
				// It cannot be mistaken for unanimous proof of noncommit.
				var now time.Time
				if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
					t.Fatal(err)
				}
				record, err := issue.Materialize(now.UTC())
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := repo.cipher.sealCaptcha(ctx, b, record)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(envelope)
				if mode == "corrupt-response" {
					envelope[len(envelope)-1] ^= 1
				}
				link := bindingDigest(b)
				if mode == "foreign-binding" {
					link[0] ^= 1
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO risk_store.captcha_issued_evidence VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'issued',$14)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.AnonymousFlowID, link[:], record.IntentDigest[:], record.ProofDigest[:], record.EvidenceDigest[:], int64(record.KeyVersion), record.Hostname, record.IssuedAt, record.ExpiresAt, envelope); err != nil {
					t.Fatal(err)
				}
				var row captchaRecoveryRow
				if err := pool.Raw().QueryRow(ctx, `SELECT user_id,anonymous_flow_id,command_purpose,binding_digest,intent_digest,proof_digest,evidence_digest,key_version,hostname,issued_at,expires_at,state,response_envelope FROM risk_store.captcha_issued_evidence WHERE command_id=$1`, id).Scan(&row.user, &row.flow, &row.purpose, &row.binding, &row.intent, &row.proof, &row.lookup, &row.key, &row.record.Hostname, &row.record.IssuedAt, &row.record.ExpiresAt, &row.state, &row.envelope); err != nil {
					t.Fatal(err)
				}
				defer clear(row.envelope)
				status, err := repo.classifyCaptchaRecovery(ctx, b, &row)
				if mode == "authentic-positive" {
					if err != nil || status != identitypostgres.RecoveryCommitted {
						t.Fatal("authentic retained participant classification", err)
					}
				} else if err == nil || status != identitypostgres.RecoveryUnknown {
					t.Fatal("unauthentic retained participant classification", err)
				}
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
			result, _ := c.RecoverFeatureCommand(ctx, q, caller)
			if result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("unresolved participant was classified terminal")
			}
			var state string
			var generation string
			if err := pool.Raw().QueryRow(ctx, `SELECT state,generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&state, &generation); err != nil || state != "pending" || generation != "1" {
				t.Fatal("unresolved recovery altered command ownership", err)
			}
		})
	}
}
