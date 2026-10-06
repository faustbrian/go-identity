package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCaptchaCustodyChecksSelectedConfigurationWithoutExecutor(t *testing.T) {
	c, p, record := captchaNativeFixture(t, captchaFlowInput())
	c.Clock, c.Verify, c.Executor = nil, nil, nil
	custody, err := NewCaptchaEvidenceCustody(c)
	if err != nil {
		t.Fatal("static custody requires operational callbacks", err)
	}
	if err := custody.ValidateConfiguration(p.Binding.PolicyVersion, c.Keys); err != nil {
		t.Fatal(err)
	}
	issue, err := custody.RestoreCaptchaIssue(p)
	if err != nil || !reflect.DeepEqual(issue.Prepared(), p) {
		t.Fatal("original signed custody changed", err)
	}
	got, err := issue.Materialize(record.IssuedAt)
	if err != nil || got != record {
		t.Fatal("original candidate changed", err)
	}
	if _, err := issue.Materialize(p.ExpiresAt); !errors.Is(err, ErrInvalidEvidenceExecution) {
		t.Fatal("expired original renewed")
	}
	c.Hostnames[0] = "other.example"
	c.Keys[0] = EvidenceKey{}
	if _, err := custody.RestoreCaptchaIssue(p); err != nil {
		t.Fatal("caller changed copied profile", err)
	}
	if err := custody.ValidateConfiguration(p.Binding.PolicyVersion+1, []EvidenceKey{custody.state.config.Keys[0]}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("wrong policy admitted")
	}
	if err := custody.ValidateConfiguration(p.Binding.PolicyVersion, nil); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("missing retained key admitted")
	}
	if _, err := json.Marshal(custody); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatal("serialized retained custody")
	}
	if _, err := (CaptchaEvidenceCustody{}).RestoreCaptchaIssue(p); !errors.Is(err, ErrInvalidEvidenceExecution) {
		t.Fatal("zero custody restored")
	}
}

func TestCaptchaCustodyDropsRuntimeAndKeepsCompleteRetainedKeys(t *testing.T) {
	c, p, _ := captchaNativeFixture(t, captchaFlowInput())
	second, err := NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.Keys = append(c.Keys, second)
	c.Clock = func() time.Time { panic("clock must not run") }
	c.Verify = func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error) {
		panic("provider must not run")
	}
	var typedNil *captchaExecutor
	c.Executor = typedNil
	if _, err := NewCaptchaEvidenceIssuer(c); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("runtime issuer accepted typed-nil executor")
	}
	custody, err := NewCaptchaEvidenceCustody(c)
	if err != nil {
		t.Fatal(err)
	}
	if custody.state.config.Clock != nil || custody.state.config.Verify != nil || custody.state.config.Executor != nil {
		t.Fatal("runtime resource retained")
	}
	if err := custody.ValidateConfiguration(p.Binding.PolicyVersion, []EvidenceKey{second, c.Keys[0]}); err != nil {
		t.Fatal("retained order changed policy", err)
	}
	if err := custody.ValidateConfiguration(p.Binding.PolicyVersion, []EvidenceKey{c.Keys[0], c.Keys[0]}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("duplicate hides retained key")
	}
	if _, err := custody.RestoreCaptchaIssue(p); err != nil {
		t.Fatal("newer retained key replaced original", err)
	}
	if got := fmt.Sprintf("%#v", custody); got != "risk.CaptchaEvidenceCustody(redacted)" {
		t.Fatal("diagnostics disclosed custody")
	}
	if _, err := custody.MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
		t.Fatal("text disclosed custody")
	}
	for _, change := range []func(*CaptchaEvidenceIssuerConfig){
		func(c *CaptchaEvidenceIssuerConfig) { c.API = strings.Repeat("x", 65) },
		func(c *CaptchaEvidenceIssuerConfig) { c.Replay = CaptchaReplayPolicy{} },
		func(c *CaptchaEvidenceIssuerConfig) { c.Keys = nil },
		func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = nil },
		func(c *CaptchaEvidenceIssuerConfig) { c.Lifetime = 0 },
		func(c *CaptchaEvidenceIssuerConfig) { c.Timeout = 0 },
	} {
		copy := c
		change(&copy)
		if got, err := NewCaptchaEvidenceCustody(copy); !errors.Is(err, ErrInvalidPolicy) || got.state != nil {
			t.Fatal("static bounds weakened")
		}
	}
}

func TestCaptchaCustodyRejectsDifferentCurrentProfile(t *testing.T) {
	for _, change := range []func(*CaptchaEvidenceIssuerConfig){
		func(c *CaptchaEvidenceIssuerConfig) { c.ExpectedAction = "signup" },
		func(c *CaptchaEvidenceIssuerConfig) { c.Hostnames = []string{"other.example"} },
		func(c *CaptchaEvidenceIssuerConfig) { c.Tier = "enterprise" },
	} {
		c, p, _ := captchaNativeFixture(t, captchaFlowInput())
		change(&c)
		custody, err := NewCaptchaEvidenceCustody(c)
		if err != nil {
			t.Fatal("valid different startup profile rejected", err)
		}
		if got, err := custody.RestoreCaptchaIssue(p); !errors.Is(err, ErrInvalidEvidenceExecution) || got.state != nil {
			t.Fatal("foreign selected profile admitted")
		}
	}
}
