package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
)

// This boundary owner proves service admission and observation, not PostgreSQL
// locking, native session eligibility or transactional one-time consumption.
type privacyServiceOwner struct {
	caps             capability.Service
	receipt          CommandResult
	err              error
	execute, recover int
	panicExecute     bool
	cancel           context.CancelFunc
	delay            time.Duration
}

func (o *privacyServiceOwner) Execute(ctx context.Context, c Command) (CommandResult, error) {
	o.execute++
	if o.panicExecute {
		panic("sensitive owner failure")
	}
	intent, ok := c.RequestPrivacyExport()
	proof, present := c.PrivacyExportProof()
	if !ok || !present {
		return CommandResult{}, errors.New("missing original custody")
	}
	grant, err := o.caps.Verify(ctx, proof, capability.Purpose(privacyExportRequestOperation), "identity-backend")
	if err != nil || grant.Payload().ID != intent.Proof.Payload().ID {
		return CommandResult{}, errors.New("original proof not verifiable")
	}
	if o.cancel != nil {
		o.cancel()
	}
	if o.delay > 0 {
		privacyOwnerWait(ctx, o.delay)
	}
	return o.receipt, o.err
}
func (o *privacyServiceOwner) Recover(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
	o.recover++
	if o.delay > 0 {
		privacyOwnerWait(ctx, o.delay)
	}
	if q.CommandID != o.receipt.Binding.CommandID || q.TenantID != o.receipt.Binding.TenantID || q.UserID != o.receipt.Binding.UserID || q.ActorID != o.receipt.Binding.ActorID || q.ActorKind != o.receipt.Binding.ActorKind || q.OperationID != privacyExportRequestOperation || q.RecordID != "" {
		return CommandResult{}, errors.New("changed recovery scope")
	}
	return o.receipt, o.err
}
func privacyOwnerWait(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

type privacyExpiringAuthorizer struct{ expires time.Time }

func (a privacyExpiringAuthorizer) Decide(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	outcome := authorization.Deny
	if r.Environment.Time.Before(a.expires) {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 1}, nil
}

type privacyCountingClock struct{ samples int }

func (c *privacyCountingClock) Now() time.Time { c.samples++; return queryClock{}.Now() }

func TestPrivacyServiceDisclosureUsesElapsedCurrentDecisionTime(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		s, r, o := privacyServiceFixture(t)
		clock := &privacyCountingClock{}
		s.config.Query.Clock = clock
		s.policy.policy.authorize, _ = authorization.NewDecisionService(privacyExpiringAuthorizer{expires: queryClock{}.Now().Add(10 * time.Millisecond)})
		o.delay = 30 * time.Millisecond
		var got PrivacyExportResult
		var err error
		if recovery {
			got, err = s.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope})
		} else {
			got, err = s.Request(context.Background(), r)
		}
		var denied ForbiddenError
		if !errors.As(err, &denied) || got.CommitOutcome != CommitOutcomeCommitted || got.ExportID != "" || got.Status != "" || clock.samples != 1 {
			t.Fatal("expired policy disclosed queued result", recovery, got.CommitOutcome, clock.samples, err)
		}
	}
}

func privacyServiceFixture(t *testing.T) (*PrivacyExportService, PrivacyExportRequest, *privacyServiceOwner) {
	t.Helper()
	intent, receipt, key := privacyReceiptFixture(t)
	f := newQueryFixture(t)
	config := PrivacyExportConfig{Query: f.service.config, ProofIssuer: "https://identity.example", ProofAudience: "identity-backend", MaximumProofAge: time.Minute, EvidenceKeys: []PrivacyExportEvidenceKey{key}}
	config.Query.PolicyID = intent.Binding.PolicyID
	signer, _ := capability.NewHMACSHA256Signer("privacy-key", []byte("0123456789abcdef0123456789abcdef"))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "privacy-key", Verifier: verifier}})
	caps, err := capability.NewService(capability.ServiceConfig{Signer: signer, Resolver: keys, Clock: func() time.Time { return queryClock{}.Now() }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	now := queryClock{}.Now()
	payload, err := BuildPrivacyExportProofPayload(PrivacyExportProofSpec{Command: intent, Issuer: config.ProofIssuer, Audience: config.ProofAudience, ID: "privacy-proof", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := caps.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.request.Context
	scope.Request.Subject.ID = authorization.SubjectID(intent.Binding.UserID)
	scope.Request.Tenant = authorization.TenantID(intent.Binding.TenantID)
	scope.Request.Resource.ID = authorization.ResourceID(intent.Binding.UserID)
	scope.Request.Action = authorization.Action(privacyExportRequestOperation)
	owner := &privacyServiceOwner{caps: caps, receipt: receipt}
	redact := func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		d, e := queryRedact(ctx, in)
		d.PolicyID = config.Query.PolicyID
		return d, e
	}
	service, err := NewPrivacyExportService(owner, caps, f.service.authorize, redact, config)
	if err != nil {
		t.Fatal(err)
	}
	return service, PrivacyExportRequest{Intent: intent, Proof: proof, ActorScope: scope}, owner
}
func TestPrivacyServiceAdmitsOriginalProofAndRecoversWithoutProof(t *testing.T) {
	s, r, o := privacyServiceFixture(t)
	got, err := s.Request(context.Background(), r)
	if err != nil || got.CommitOutcome != CommitOutcomeCommitted || got.ExportID != o.receipt.PrivacyExport.Snapshot.ExportID || got.Status != PrivacyExportQueued {
		t.Fatal("admission failed", err)
	}
	// Recovery retains unsigned intent and current scope, not an expiring bearer.
	recovered, err := s.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope})
	if err != nil || recovered != got || o.execute != 1 || o.recover != 1 {
		t.Fatal("recovery changed observation", err)
	}
}
func TestPrivacyServiceRejectsSubstitutionBeforeMutation(t *testing.T) {
	for _, mutate := range []func(*PrivacyExportRequest){
		func(r *PrivacyExportRequest) { r.Intent.MaximumBytes++ },
		func(r *PrivacyExportRequest) { r.Intent.Binding.PolicyID = "other-policy" },
		func(r *PrivacyExportRequest) { r.ActorScope.Request.Subject.ID = "other-human" },
		func(r *PrivacyExportRequest) { r.ActorScope.Request.Tenant = "other-tenant" },
		func(r *PrivacyExportRequest) { r.Proof = capability.Proof{} },
	} {
		s, r, o := privacyServiceFixture(t)
		mutate(&r)
		got, err := s.Request(context.Background(), r)
		if err == nil || o.execute != 0 || got.ExportID != "" || got.CommitOutcome != CommitOutcomeNotCommitted {
			t.Fatal("substitution reached mutation")
		}
	}
}
func TestPrivacyServicePreservesKnownOutcomeOnFailure(t *testing.T) {
	for _, mode := range []string{"transport", "cancel", "redaction", "redaction-panic", "bad-mac", "panic"} {
		t.Run(mode, func(t *testing.T) {
			s, r, o := privacyServiceFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expected := CommitOutcomeCommitted
			switch mode {
			case "transport":
				o.err = errors.New("sensitive transport error")
			case "cancel":
				o.cancel = cancel
			case "redaction":
				s.policy.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
					return RedactionPolicyDecision{}, nil
				}
			case "redaction-panic":
				s.policy.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
					panic("private callback failure")
				}
			case "bad-mac":
				o.receipt.PrivacyExport.Snapshot.Digest[0]++
				expected = CommitOutcomeUnknown
			case "panic":
				o.panicExecute = true
				expected = CommitOutcomeUnknown
			}
			got, err := s.Request(ctx, r)
			if err == nil || got.ExportID != "" || got.Status != "" || got.CommitOutcome != expected {
				t.Fatal("failure fabricated rollback or disclosed data", got.CommitOutcome, err)
			}
		})
	}
}
func TestPrivacyServiceRejectsChangedRecoveryIntent(t *testing.T) {
	s, r, o := privacyServiceFixture(t)
	r.Intent.SessionVersion++
	got, err := s.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope})
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.ExportID != "" || o.recover != 1 {
		t.Fatal("wrong recovery intent accepted", err)
	}
}

func TestPrivacyServiceConfiguredTrustAndKnownNoncommittedOutcomes(t *testing.T) {
	for _, change := range []func(*PrivacyExportService){
		func(s *PrivacyExportService) { s.config.ProofIssuer = "https://untrusted.example" },
		func(s *PrivacyExportService) { s.config.ProofAudience = "other-backend" },
		func(s *PrivacyExportService) { s.config.MaximumProofAge = 30 * time.Second },
	} {
		s, r, o := privacyServiceFixture(t)
		change(s)
		got, err := s.Request(context.Background(), r)
		if err == nil || o.execute != 0 || got.CommitOutcome != CommitOutcomeNotCommitted || got.ExportID != "" {
			t.Fatal("unconfigured proof accepted")
		}
	}
	for _, outcome := range []CommitOutcome{CommitOutcomeNotCommitted, CommitOutcomeConflict, CommitOutcomeInProgress, CommitOutcomeUnknown} {
		s, r, o := privacyServiceFixture(t)
		o.receipt.Outcome, o.receipt.PrivacyExport, o.receipt.AuditEventID = outcome, nil, ""
		if outcome == CommitOutcomeInProgress {
			o.receipt.RetryAfter = time.Second
		}
		got, err := s.Request(context.Background(), r)
		if err == nil || got.CommitOutcome != outcome || got.ExportID != "" {
			t.Fatal("known outcome lost", outcome, err)
		}
	}
}

func TestPrivacyServiceDeniedRecoveryDoesNotInventRollback(t *testing.T) {
	s, r, o := privacyServiceFixture(t)
	r.ActorScope.Request.Subject.ID = "other-human"
	got, err := s.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope})
	if err == nil || got.CommitOutcome != CommitOutcomeUnknown || o.recover != 0 || got.ExportID != "" {
		t.Fatal("denied observation invented rollback")
	}
}

func TestPrivacyServiceRetainsHistoricalKeysAndRejectsMissingKey(t *testing.T) {
	s, r, o := privacyServiceFixture(t)
	newKey, _ := NewPrivacyExportEvidenceKey(99, [32]byte{9})
	s.config.EvidenceKeys = append([]PrivacyExportEvidenceKey{newKey}, s.config.EvidenceKeys...)
	got, err := s.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope})
	if err != nil || got.ExportID != o.receipt.PrivacyExport.Snapshot.ExportID {
		t.Fatal("rotation discarded old key", err)
	}
	s.config.EvidenceKeys = []PrivacyExportEvidenceKey{newKey}
	got, err = s.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope})
	if err == nil || got.ExportID != "" || got.CommitOutcome != CommitOutcomeUnknown {
		t.Fatal("missing recorded key accepted")
	}
}

func TestPrivacyServiceConfigurationAndMetadataCustody(t *testing.T) {
	s, r, _ := privacyServiceFixture(t)
	for _, change := range []func(*PrivacyExportConfig){
		func(c *PrivacyExportConfig) { c.EvidenceKeys = nil },
		func(c *PrivacyExportConfig) { c.EvidenceKeys = []PrivacyExportEvidenceKey{{}} },
		func(c *PrivacyExportConfig) { c.EvidenceKeys = append(c.EvidenceKeys, c.EvidenceKeys[0]) },
		func(c *PrivacyExportConfig) { c.MaximumProofAge = 0 },
		func(c *PrivacyExportConfig) { c.MaximumProofAge = 6 * time.Minute },
	} {
		config := s.config
		config.EvidenceKeys = append([]PrivacyExportEvidenceKey(nil), config.EvidenceKeys...)
		change(&config)
		if _, err := NewPrivacyExportService(s.uow, s.caps, s.policy.policy.authorize, s.policy.policy.redact, config); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	config := s.config
	config.EvidenceKeys = append([]PrivacyExportEvidenceKey(nil), config.EvidenceKeys...)
	copyService, err := NewPrivacyExportService(s.uow, s.caps, s.policy.policy.authorize, s.policy.policy.redact, config)
	if err != nil {
		t.Fatal(err)
	}
	config.EvidenceKeys[0] = PrivacyExportEvidenceKey{}
	if _, err := copyService.Recover(context.Background(), PrivacyExportRecoveryRequest{Intent: r.Intent, ActorScope: r.ActorScope}); err != nil {
		t.Fatal("configuration keys aliased", err)
	}
	r.Intent.Proof, _ = s.caps.Verify(context.Background(), r.Proof, capability.Purpose(privacyExportRequestOperation), "identity-backend")
	metadata, err := NewPrivacyExportRequestCommand(r.Intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := metadata.PrivacyExportProof(); ok {
		t.Fatal("metadata manufactured bearer custody")
	}
}

func TestPrivacyServiceRuntimeCompositionCannotBeDisclosed(t *testing.T) {
	s, _, _ := privacyServiceFixture(t)
	if strings.Contains(fmt.Sprintf("%#v", *s), s.config.ProofIssuer) {
		t.Fatal("runtime composition disclosed trusted configuration")
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("runtime composition serialized")
	}
}
