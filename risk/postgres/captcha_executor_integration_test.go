//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// Retain the authentic provisional command for restart without retaining a
// provider token. Every outcome comes from the real owned executor.
type captchaSubmissionCapture struct {
	delegate *CaptchaExecutor
	prepared risk.PreparedCaptchaEvidence
}

func (c *captchaSubmissionCapture) Resolve(ctx context.Context, i risk.CaptchaEvidenceIntent) (risk.CaptchaEvidenceExecution, error) {
	return c.delegate.Resolve(ctx, i)
}
func (c *captchaSubmissionCapture) Execute(ctx context.Context, i risk.CaptchaEvidenceIssue) (risk.CaptchaEvidenceExecution, error) {
	c.prepared = i.Prepared()
	return c.delegate.Execute(ctx, i)
}

// The policy oracle owns literal expected inputs independently of the executor.
// Missing or forged flow attributes make real admission/disclosure deny.
type captchaFlowPolicy struct {
	flow            risk.FlowContextInput
	caller          authorization.DecisionContext
	admission, deny bool
	calls           atomic.Int32
}

func (p *captchaFlowPolicy) Decide(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	p.calls.Add(1)
	r, want := dc.Request, p.caller.Request
	match := r.Subject.ID == want.Subject.ID && r.Subject.Kind == want.Subject.Kind && r.Tenant == want.Tenant && r.Action == want.Action && r.Resource.Type == want.Resource.Type && r.Resource.ID == want.Resource.ID
	for name, expected := range map[string]string{"flow-kind": string(p.flow.Kind), "operation": string(p.flow.Operation), "pre-auth": p.flow.PreAuthTransaction, "session": p.flow.Session, "actor": p.flow.Actor, "challenge": p.flow.ChallengeID, "request": p.flow.RequestFingerprint} {
		actual, ok := r.Attributes[authorization.AttributeName("identity.captcha."+name)].String()
		match = match && ok && actual == expected
	}
	admission, ok := r.Resource.Attributes["identity.command.read-admission"].Bool()
	match = match && ok && admission == p.admission
	recovery, ok := r.Resource.Attributes["identity.command.recovery"].Bool()
	match = match && ok && recovery != p.admission
	outcome := authorization.Allow
	if !match || p.deny {
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: 1}, nil
}

func testPublicCaptchaExecutor(t *testing.T, ctx context.Context, pool *database.Pool, dsn, databaseName string, production ...captchaProductionEffects) {
	prefix := ""
	if len(production) == 1 {
		prefix = "production-"
	}
	for _, variant := range []string{"pre-auth-anonymous", "pre-auth-subject", "authenticated", "admin-subject", "admin-anonymous", "admin-session", "lost-ack", "audit-rollback", "outbox-rollback"} {
		t.Run(variant, func(t *testing.T) {
			flow := captchaFlowFixture()
			flow.ChallengeID = "public-" + prefix + variant
			if variant == "pre-auth-subject" {
				flow.Subject, flow.AnonymousFlow = "subject", ""
			}
			if variant == "authenticated" {
				flow.Kind, flow.Subject, flow.AnonymousFlow, flow.PreAuthTransaction, flow.Session = risk.FlowAuthenticated, "subject", "", "", "session"
			}
			if variant == "admin-subject" || variant == "admin-anonymous" || variant == "admin-session" {
				flow.Kind, flow.PreAuthTransaction, flow.Actor = risk.FlowAdministrator, "", "administrator"
				if variant != "admin-anonymous" {
					flow.Subject, flow.AnonymousFlow = "subject", ""
				}
				if variant == "admin-session" {
					flow.Session = "admin-session"
				}
			}
			at := time.Now().UTC()
			_, key, profile := captchaConfiguredFixture(t, flow, at)
			custody, err := risk.NewCaptchaEvidenceCustody(profile)
			if err != nil {
				t.Fatal(err)
			}
			repo, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", CaptchaCustody: []risk.CaptchaEvidenceCustody{custody}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(id))
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "captcha-service"}, Tenant: "tenant", Action: "identity.risk.captcha-issue", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: "anonymous-flow"}}}
			if flow.Subject != "" {
				caller.Request.Resource.Type, caller.Request.Resource.ID = "identity.user", authorization.ResourceID(flow.Subject)
			}
			if flow.Actor != "" {
				caller.Request.Subject.Kind, caller.Request.Subject.ID = authorization.SubjectUser, authorization.SubjectID(flow.Actor)
			}
			admissionPolicy := &captchaFlowPolicy{flow: flow, caller: caller.Clone(), admission: true}
			recoveryPolicy := &captchaFlowPolicy{flow: flow, caller: caller.Clone()}
			read := &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: recoveryPolicy}
			admit := &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: admissionPolicy}
			// Conflicting supplied values must be replaced by trusted composition.
			caller.Request.Attributes = authorization.Attributes{"identity.captcha.operation": authorization.StringValue("forged-operation"), "identity.captcha.session": authorization.StringValue("forged-session")}
			cfg := CaptchaExecutorConfig{Flow: flow, Executor: ExecutorConfig{Pool: pool, Repository: repo, Audit: &issuanceAudit{fail: variant == "audit-rollback"}, Lifecycle: &issuanceOutbox{}, Coordinator: identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: read, AdmissionPolicy: admit}, Caller: caller, PolicyID: "captcha-policy", RetentionPolicyVersion: 1}}
			cfg.Executor.Lifecycle = &issuanceOutbox{fail: variant == "outbox-rollback"}
			if len(production) == 1 {
				cfg.Executor.Audit, cfg.Executor.Lifecycle = production[0].audit, production[0].lifecycle
				if variant == "audit-rollback" {
					cfg.Executor.Audit = captchaProductionAuditFailure{cfg.Executor.Audit}
				}
				if variant == "outbox-rollback" {
					cfg.Executor.Lifecycle = captchaProductionOutboxFailure{cfg.Executor.Lifecycle}
				}
			}
			var fault *commitAckFault
			if variant == "lost-ack" {
				cfg.Executor.Pool, fault = newCommitAckPool(t, ctx, dsn, databaseName, raw)
			}
			executor, err := NewCaptchaExecutor(cfg)
			if err != nil {
				t.Fatal("public executor unavailable", err)
			}
			if variant == "pre-auth-anonymous" {
				for _, unrelated := range []int{121, 122} {
					boundary := cfg
					boundary.Executor.Caller = cfg.Executor.Caller.Clone()
					boundary.Executor.Caller.Request.Attributes = authorization.Attributes{}
					for n := 0; n < unrelated; n++ {
						boundary.Executor.Caller.Request.Attributes[authorization.AttributeName("unrelated."+strconv.Itoa(n))] = authorization.StringValue("bounded")
					}
					boundedExecutor, err := NewCaptchaExecutor(boundary)
					if unrelated == 122 {
						if err == nil {
							t.Fatal("constructor accepted 129 final policy attributes")
						}
						continue
					}
					if err != nil {
						t.Fatal("constructor rejected 128 final policy attributes", err)
					}
					// Exact-limit accepted composition must also execute, not just
					// satisfy the constructor while failing the consumer's gate.
					boundaryProfile := profile
					boundaryProfile.Executor, boundaryProfile.Clock = boundedExecutor, time.Now
					boundaryIssuer, err := risk.NewCaptchaEvidenceIssuer(boundaryProfile)
					if err != nil {
						t.Fatal(err)
					}
					boundaryID, err := identity.NewCommandID()
					if err != nil {
						t.Fatal(err)
					}
					boundaryFlow, err := risk.NewFlowContext(flow)
					if err != nil {
						t.Fatal(err)
					}
					boundaryToken := []byte("synthetic-" + prefix + "exact-policy-limit-token")
					boundaryIntent, err := boundaryIssuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: string(boundaryID), Flow: boundaryFlow}, boundaryToken)
					if err != nil {
						t.Fatal(err)
					}
					boundaryResult, err := boundaryIssuer.Issue(ctx, boundaryIntent, boundaryToken)
					if err != nil || boundaryResult.Outcome != risk.EvidenceCommitted {
						t.Fatal("exact policy limit composition is unusable", err)
					}
				}
			}
			caller.Request.Attributes["identity.captcha.session"] = authorization.StringValue("mutated-after-construction")
			capture := &captchaSubmissionCapture{delegate: executor}
			profile.Executor, profile.Clock = capture, time.Now
			verifications := 0
			verify := profile.Verify
			profile.Verify = func(ctx context.Context, req risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
				verifications++
				return verify(ctx, req)
			}
			issuer, err := risk.NewCaptchaEvidenceIssuer(profile)
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := risk.NewFlowContext(flow)
			if err != nil {
				t.Fatal(err)
			}
			token := []byte("synthetic-public-captcha-" + prefix + variant)
			intent, err := issuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: string(id), Flow: trusted}, token)
			if err != nil {
				t.Fatal(err)
			}
			result, issueErr := issuer.Issue(ctx, intent, token)
			if variant == "lost-ack" {
				if result.Outcome != risk.EvidenceUnknown || result.Evidence.Reference.Reveal() != "" || fault.hits.Load() != 1 {
					t.Fatal("lost acknowledgement leaked or did not exercise actual commit", issueErr)
				}
			} else if variant == "audit-rollback" || variant == "outbox-rollback" {
				if result.Outcome == risk.EvidenceCommitted || result.Evidence.Reference.Reveal() != "" {
					t.Fatal("rolled back evidence disclosed", issueErr)
				}
			} else if issueErr != nil || result.Outcome != risk.EvidenceCommitted || result.Evidence.Reference.Reveal() == "" {
				t.Fatal("public issuance not committed", issueErr)
			}
			var evidence, audits, lifecycle int
			query := `SELECT (SELECT count(*) FROM risk_store.captcha_issued_evidence WHERE command_id=$1),(SELECT count(*) FROM public.risk_audit WHERE command_id=$2 AND record->>'outcome'='1'),(SELECT count(*) FROM public.risk_outbox WHERE command_id=$2)`
			if len(production) == 1 {
				query = `SELECT (SELECT count(*) FROM risk_store.captcha_issued_evidence WHERE command_id=$1),(SELECT count(*) FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1 AND r.outcome=1),(SELECT count(*) FROM public.outbox_messages m JOIN public.identity_outbox_bindings b ON b.effect_id=m.id WHERE b.command_id=$1 AND m.metadata->>'identity.command_id'=$2)`
			}
			if err := pool.Raw().QueryRow(ctx, query, raw, string(id)).Scan(&evidence, &audits, &lifecycle); err != nil {
				t.Fatal(err)
			}
			if variant == "audit-rollback" || variant == "outbox-rollback" {
				if evidence != 0 || audits != 0 || lifecycle != 0 {
					t.Fatal("rollback leaked atomic effects")
				}
				if len(production) == 1 {
					var bindings int
					if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1`, raw).Scan(&bindings); err != nil || bindings != 0 {
						t.Fatal("rollback retained lifecycle binding", err, bindings)
					}
				}
				return
			}
			if evidence != 1 || audits != 1 || lifecycle != 1 {
				t.Fatal("issuance effects were not atomic")
			}
			if len(production) == 1 {
				var auditBindings, outboxBindings int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&auditBindings, &outboxBindings); err != nil || auditBindings != 1 || outboxBindings != 1 {
					t.Fatal("production binding cardinality", err, auditBindings, outboxBindings)
				}
			}
			recovered, err := issuer.Recover(ctx, intent)
			if err != nil || recovered.Outcome != risk.EvidenceCommitted || verifications != 1 {
				t.Fatal("public recovery failed or verified again", err)
			}
			if admissionPolicy.calls.Load() == 0 || recoveryPolicy.calls.Load() == 0 {
				t.Fatal("separate policies were not reached")
			}
			if variant != "lost-ack" && recovered != result {
				t.Fatal("original response changed")
			}
			if len(production) == 1 {
				var auditPayload, outboxPayload string
				// bytea is hexadecimal in row JSON. Inspect decoded canonical
				// payloads too, or a bearer inside them would evade this oracle.
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT row_to_json(r)::text || convert_from(r.canonical_record,'UTF8') FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1),(SELECT row_to_json(m)::text || convert_from(m.payload,'UTF8') FROM public.outbox_messages m JOIN public.identity_outbox_bindings b ON b.effect_id=m.id WHERE b.command_id=$1)`, raw).Scan(&auditPayload, &outboxPayload); err != nil {
					t.Fatal(err)
				}
				for _, payload := range []string{auditPayload, outboxPayload} {
					if strings.Contains(payload, string(token)) || strings.Contains(payload, recovered.Evidence.Reference.Reveal()) {
						t.Fatal("production projection disclosed bearer or provider input")
					}
				}
			}
			// Replaying the exact command does not call the provider again.
			replayed, err := issuer.Issue(ctx, intent, token)
			if err != nil || replayed != recovered || verifications != 1 {
				t.Fatal("exact replay reevaluated or changed response", err)
			}
			// An independently valid but foreign challenge/session/pre-auth
			// context cannot use this verified runtime scope, even before SQL.
			foreignFlow := flow
			foreignFlow.ChallengeID += "-foreign"
			foreignContext, err := risk.NewFlowContext(foreignFlow)
			if err != nil {
				t.Fatal(err)
			}
			foreignID, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			foreignIntent, err := issuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: string(foreignID), Flow: foreignContext}, token)
			if err != nil {
				t.Fatal(err)
			}
			foreignResult, err := issuer.Issue(ctx, foreignIntent, token)
			if err != nil || foreignResult.Outcome != risk.EvidenceDenied || foreignResult.Evidence.Reference.Reveal() != "" || verifications != 1 {
				t.Fatal("foreign flow admitted or verified", err)
			}
			foreignRaw, _ := base64.RawURLEncoding.DecodeString(string(foreignID))
			var claims int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, foreignRaw).Scan(&claims); err != nil || claims != 0 {
				t.Fatal("foreign flow reached reservation", err)
			}
			// A fresh authorized instance restores signed custody, without tokens,
			// and recovers an expired historical result without renewal.
			restartRepo, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", CaptchaCustody: []risk.CaptchaEvidenceCustody{custody}})
			if err != nil {
				t.Fatal(err)
			}
			restartConfig := cfg
			restartConfig.Executor.Repository, restartConfig.Executor.Pool = restartRepo, pool
			restartExecutor, err := NewCaptchaExecutor(restartConfig)
			if err != nil {
				t.Fatal(err)
			}
			if restartExecutor.executor.coordinator == executor.executor.coordinator || restartRepo == repo {
				t.Fatal("restart reused original runtime")
			}
			profile.Executor = restartExecutor
			profile.Verify = func(context.Context, risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
				t.Fatal("restart verified provider")
				return risk.CaptchaObservation{}, nil
			}
			profile.Clock = func() time.Time { return at.Add(2 * time.Minute) }
			restarted, err := risk.NewCaptchaEvidenceIssuer(profile)
			if err != nil {
				t.Fatal(err)
			}
			original, err := restarted.RestoreCaptchaIssue(capture.prepared)
			if err != nil {
				t.Fatal(err)
			}
			historical, err := restarted.Recover(ctx, original.Intent())
			if err != nil || historical != recovered || verifications != 1 {
				t.Fatal("restart changed historical result", err)
			}
			deniedCfg := cfg
			deniedCfg.Executor.Coordinator.QueryPolicy = &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: issuanceDenyPolicy{}}
			denied, err := NewCaptchaExecutor(deniedCfg)
			if err != nil {
				t.Fatal(err)
			}
			profile.Executor = denied
			unauthorized, err := risk.NewCaptchaEvidenceIssuer(profile)
			if err != nil {
				t.Fatal(err)
			}
			foreign, err := unauthorized.RestoreCaptchaIssue(capture.prepared)
			if err != nil {
				t.Fatal(err)
			}
			disclosure, err := unauthorized.Recover(ctx, foreign.Intent())
			if err != nil || disclosure.Outcome != risk.EvidenceDenied || disclosure.Evidence.Reference.Reveal() != "" {
				t.Fatal("current recovery denial disclosed original", err)
			}
			// Current admission denial on an absent command performs no provider
			// verification, command reservation or disclosure.
			admissionDenied := cfg
			admissionDenied.Executor.Coordinator.AdmissionPolicy = &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: &captchaFlowPolicy{flow: flow, caller: caller.Clone(), admission: true, deny: true}}
			denyExecutor, err := NewCaptchaExecutor(admissionDenied)
			if err != nil {
				t.Fatal(err)
			}
			profile.Executor, profile.Clock = denyExecutor, time.Now
			denyIssuer, err := risk.NewCaptchaEvidenceIssuer(profile)
			if err != nil {
				t.Fatal(err)
			}
			absentID, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			absentIntent, err := denyIssuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: string(absentID), Flow: trusted}, token)
			if err != nil {
				t.Fatal(err)
			}
			absentResult, err := denyIssuer.Issue(ctx, absentIntent, token)
			if err != nil || absentResult.Outcome != risk.EvidenceDenied || absentResult.Evidence.Reference.Reveal() != "" {
				t.Fatal("absent command admitted despite current denial", err)
			}
			absentRaw, _ := base64.RawURLEncoding.DecodeString(string(absentID))
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, absentRaw).Scan(&claims); err != nil || claims != 0 {
				t.Fatal("admission denial reserved command", err)
			}
			for _, change := range []func(*CaptchaExecutorConfig){
				func(c *CaptchaExecutorConfig) { c.Flow.Actor = "foreign" },
				func(c *CaptchaExecutorConfig) { c.Executor.Caller.Request.Tenant = "foreign" },
				func(c *CaptchaExecutorConfig) { c.Executor.Caller.Request.Resource.ID = "foreign" },
				func(c *CaptchaExecutorConfig) { c.Executor.Caller.Request.Action = "identity.risk.evaluate" },
				func(c *CaptchaExecutorConfig) { c.Executor.Repository = &Repository{} },
			} {
				bad := cfg
				bad.Executor.Caller = cfg.Executor.Caller.Clone()
				change(&bad)
				if _, err := NewCaptchaExecutor(bad); err == nil {
					t.Fatal("foreign constructor composition admitted")
				}
			}
		})
	}
}
