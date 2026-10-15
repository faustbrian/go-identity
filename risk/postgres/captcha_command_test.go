package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

type captchaCapture struct{ issue risk.CaptchaEvidenceIssue }

func (*captchaCapture) Resolve(_ context.Context, i risk.CaptchaEvidenceIntent) (risk.CaptchaEvidenceExecution, error) {
	return risk.NewCaptchaEvidenceExecution(i, risk.EvidenceMissing, risk.CaptchaEvidenceRecord{})
}
func (c *captchaCapture) Execute(_ context.Context, i risk.CaptchaEvidenceIssue) (risk.CaptchaEvidenceExecution, error) {
	c.issue = i
	return risk.NewCaptchaEvidenceExecution(i.Intent(), risk.EvidenceFailed, risk.CaptchaEvidenceRecord{})
}

// A real public core issuer creates native custody. This boundary only captures
// provisional input and cannot attest SQL commitment or provider interoperability.
func captchaIssueFixture(t *testing.T, flow risk.FlowContextInput) (risk.CaptchaEvidenceIssue, risk.EvidenceKey) {
	i, k, _ := captchaConfiguredFixture(t, flow, time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	return i, k
}

func captchaConfiguredFixture(t *testing.T, flow risk.FlowContextInput, now time.Time, versions ...uint32) (risk.CaptchaEvidenceIssue, risk.EvidenceKey, risk.CaptchaEvidenceIssuerConfig) {
	t.Helper()
	if len(versions) == 0 {
		versions = []uint32{1}
	}
	var keys []risk.CaptchaReplayKey
	for _, version := range versions {
		key, err := risk.NewCaptchaReplayKey(version, bytes.Repeat([]byte{byte(0x20 + version)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	return captchaConfiguredKeyFixture(t, flow, now, keys)
}

func captchaConfiguredKeyFixture(t *testing.T, flow risk.FlowContextInput, now time.Time, replayKeys []risk.CaptchaReplayKey, sites ...string) (risk.CaptchaEvidenceIssue, risk.EvidenceKey, risk.CaptchaEvidenceIssuerConfig) {
	t.Helper()
	site := "fixture-site"
	if len(sites) > 0 {
		site = sites[0]
	}
	pc := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}}
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"captcha", "status", "velocity"}
	}
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := risk.NewCaptchaReplayPolicy(risk.CaptchaReplayPolicyConfig{Policy: policy, Provider: "turnstile", Site: site, APIProfile: "siteverify/v0", ConfigurationVersion: "fixture-v1", MaxTokenBytes: 8192, Keys: replayKeys})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	capture := &captchaCapture{}
	cfg := risk.CaptchaEvidenceIssuerConfig{Replay: replay, API: "siteverify", Version: "v0", Tier: "free", Capabilities: risk.CaptchaCapabilities{Hostname: true}, Hostnames: []string{"example.com"}, Lifetime: time.Minute, Timeout: 5 * time.Second, Clock: func() time.Time { return now }, Keys: []risk.EvidenceKey{key}, Executor: capture, Verify: func(_ context.Context, req risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
		return risk.CaptchaObservation{Flow: req.Flow, CommandID: req.CommandID, Provider: "turnstile", Site: site, APIProfile: "siteverify/v0", ConfigurationVersion: "fixture-v1", API: "siteverify", Version: "v0", Tier: "free", Outcome: risk.CaptchaSolved, Hostname: risk.CaptchaString{Available: true, Value: "example.com"}, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
	}}
	issuer, err := risk.NewCaptchaEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f, err := risk.NewFlowContext(flow)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("synthetic-provider-token")
	intent, err := issuer.Prepare(risk.CaptchaEvidenceRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Flow: f}, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := issuer.Issue(context.Background(), intent, token)
	if err != nil || result.Outcome != risk.EvidenceFailed || capture.issue.Prepared().Binding.KeyVersion == 0 {
		t.Fatal("native fixture did not produce custody", err)
	}
	return capture.issue, key, cfg
}

func captchaFlowFixture() risk.FlowContextInput {
	return risk.FlowContextInput{Kind: risk.FlowPreAuth, Tenant: "tenant", Operation: "identity.password.signin", AnonymousFlow: "anonymous-flow", PreAuthTransaction: "pre-auth", ChallengeID: "challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
}

func captchaCommandBinding(p risk.PreparedCaptchaEvidence) identity.CommandBinding {
	f := p.Binding.Replay.Flow
	kind := identity.FeatureSubjectUser
	if f.AnonymousFlow != "" {
		kind = identity.FeatureSubjectAnonymousFlow
	}
	op := CaptchaIssueOperation(kind)
	actor, actorKind := "verified-service", authorization.SubjectServiceAccount
	if f.Kind == risk.FlowAdministrator {
		actor, actorKind = f.Actor, authorization.SubjectUser
	}
	return identity.CommandBinding{CommandID: identity.CommandID(p.Binding.CommandID), TenantID: identity.TenantID(f.Tenant), UserID: identity.UserID(f.Subject), AnonymousFlowID: f.AnonymousFlow, ActorID: identity.ActorID(actor), ActorKind: actorKind, OperationID: op.OperationID, PolicyID: "policy", PolicyVersion: p.Binding.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: "correlation"}
}

func TestCaptchaNativeCommandConservesAllFlowVariants(t *testing.T) {
	for _, variant := range []string{"pre-auth-anonymous", "pre-auth-subject", "authenticated", "admin-subject", "admin-anonymous", "admin-session"} {
		t.Run(variant, func(t *testing.T) {
			flow := captchaFlowFixture()
			switch variant {
			case "pre-auth-subject":
				flow.Subject, flow.AnonymousFlow = "subject", ""
			case "authenticated":
				flow.Kind, flow.Subject, flow.AnonymousFlow, flow.PreAuthTransaction, flow.Session = risk.FlowAuthenticated, "subject", "", "", "session"
			case "admin-subject", "admin-anonymous", "admin-session":
				flow.Kind, flow.PreAuthTransaction, flow.Actor = risk.FlowAdministrator, "", "administrator"
				if variant != "admin-anonymous" {
					flow.Subject, flow.AnonymousFlow = "subject", ""
				}
				if variant == "admin-session" {
					flow.Session = "admin-session"
				}
			}
			issue, key := captchaIssueFixture(t, flow)
			p := issue.Prepared()
			command, err := MapCaptchaIssue(issue, captchaCommandBinding(p))
			if err != nil {
				t.Fatal(err)
			}
			s, ok := command.Feature()
			if !ok || s.Binding.RecordID != p.Binding.CommandID || string(s.Binding.UserID) != flow.Subject || s.Binding.AnonymousFlowID != flow.AnonymousFlow {
				t.Fatal("native target scope lost")
			}
			restored, err := restoreCaptchaCommand(command, []risk.EvidenceKey{key}, 3)
			if err != nil || !reflect.DeepEqual(restored.Prepared(), p) {
				t.Fatal("native command changed signed custody", err)
			}
			for _, field := range s.Fields {
				if field.Value.Kind == identity.FeatureText && field.Value.Text == "synthetic-provider-token" {
					t.Fatal("token entered command")
				}
			}
		})
	}
}

func TestCaptchaNativeCommandRejectsAlteredCustodyAndScope(t *testing.T) {
	issue, key := captchaIssueFixture(t, captchaFlowFixture())
	b := captchaCommandBinding(issue.Prepared())
	command, err := MapCaptchaIssue(issue, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "other" },
		func(b *identity.CommandBinding) { b.UserID = "anonymous-flow" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.RecordID = "caller-target" },
		func(b *identity.CommandBinding) { b.ActorID = "" },
		func(b *identity.CommandBinding) { b.ActorKind = "anonymous" },
	} {
		wrong := b
		mutate(&wrong)
		if _, err := MapCaptchaIssue(issue, wrong); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
			t.Fatal("foreign or invalid native scope accepted", err)
		}
	}
	s, _ := command.Feature()
	for index := range s.Fields {
		for _, mode := range []string{"alter", "wrong-kind", "missing", "unknown"} {
			wrong, _ := command.Feature()
			field := &wrong.Fields[index]
			switch mode {
			case "alter":
				switch field.Value.Kind {
				case identity.FeatureText:
					field.Value.Text += "x"
				case identity.FeatureUint64:
					field.Value.Uint64++
				case identity.FeatureBytes:
					field.Value.Bytes[0] ^= 1
				case identity.FeatureTime:
					field.Value.Time = field.Value.Time.Add(time.Microsecond)
				}
			case "wrong-kind":
				field.Value = identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}
			case "missing":
				wrong.Fields = append(wrong.Fields[:index], wrong.Fields[index+1:]...)
			case "unknown":
				field.Name = "captcha.unknown"
			}
			bad, err := identity.NewFeatureCommand(wrong)
			if err != nil {
				t.Fatal("invalid structural fixture", err)
			}
			if got, err := restoreCaptchaCommand(bad, []risk.EvidenceKey{key}, 3); !errors.Is(err, risk.ErrInvalidEvidenceExecution) || !reflect.DeepEqual(got.Prepared(), risk.PreparedCaptchaEvidence{}) {
				t.Fatal("altered custody restored", mode, s.Fields[index].Name, err)
			}
		}
	}
	wrongKey, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x24}, 32), bytes.Repeat([]byte{0x25}, 32))
	for _, test := range []struct {
		keys   []risk.EvidenceKey
		policy uint64
	}{{nil, 3}, {[]risk.EvidenceKey{key}, 0}, {[]risk.EvidenceKey{key}, 4}, {[]risk.EvidenceKey{wrongKey}, 3}} {
		if _, err := restoreCaptchaCommand(command, test.keys, test.policy); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
			t.Fatal("foreign configuration restored", err)
		}
	}
	if _, err := MapCaptchaIssue(risk.CaptchaEvidenceIssue{}, b); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("zero issue accepted")
	}
	if CaptchaIssueOperation(255).Validate() == nil {
		t.Fatal("unknown subject policy accepted")
	}
	admin := captchaFlowFixture()
	admin.Kind, admin.PreAuthTransaction, admin.Actor = risk.FlowAdministrator, "", "administrator"
	adminIssue, _ := captchaIssueFixture(t, admin)
	adminBinding := captchaCommandBinding(adminIssue.Prepared())
	adminBinding.ActorID = "other-administrator"
	if _, err := MapCaptchaIssue(adminIssue, adminBinding); !errors.Is(err, risk.ErrInvalidEvidenceExecution) {
		t.Fatal("signed admin actor substituted", err)
	}
}
