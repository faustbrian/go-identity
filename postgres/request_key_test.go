package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// RK-03: independent literal canonical CBOR, not the production map encoder.
func TestRequestKeyFingerprintIndependentVector(t *testing.T) {
	scope := RequestKeyScope{TenantID: "t", ActorID: "a", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "r"}
	fields := []identity.FeatureField{{Name: "x", Value: identity.FeatureValue{Kind: identity.FeatureBool}}}
	key := [32]byte{1}
	inner := hmac.New(sha256.New, key[:])
	inner.Write([]byte("identity-command-secret-v1"))
	var pathLength [4]byte
	binary.BigEndian.PutUint32(pathLength[:], uint32(len("request.x")))
	inner.Write(pathLength[:])
	inner.Write([]byte("request.x"))
	var rawLength [8]byte
	binary.BigEndian.PutUint64(rawLength[:], 1)
	inner.Write(rawLength[:])
	inner.Write([]byte{0xf4})
	prefix, _ := hex.DecodeString("a8656163746f72616165726f7574656172666669656c6473a16178a2646b696e64056576616c75655820")
	suffix, _ := hex.DecodeString("666d6574686f6464504f53546674656e616e7461746770726f66696c65781a6964656e746974792d726571756573742d696e74656e742d76316a6163746f725f6b696e6464757365726e706f6c6963795f76657273696f6e09")
	canonical := append(append(prefix, inner.Sum(nil)...), suffix...)
	outer := hmac.New(sha256.New, key[:])
	outer.Write(canonical)
	var want [32]byte
	copy(want[:], outer.Sum(nil))
	got, safe, err := requestIntentFingerprint(scope, fields, 9, key)
	if err != nil || got != want {
		t.Fatal("request intent diverges from independent canonical vector")
	}
	if bytes.Contains(safe, []byte("false")) || bytes.Contains(safe, inner.Sum(nil)) {
		t.Fatal("safe collision metadata contains scalar values")
	}
	changed, _, err := requestIntentFingerprint(scope, nil, 9, key)
	if err != nil || changed == got {
		t.Fatal("absent field collapsed into explicit false")
	}
	fields[0].Value = identity.FeatureValue{Kind: identity.FeatureUint64}
	changed, kindSafe, err := requestIntentFingerprint(scope, fields, 9, key)
	if err != nil || changed == got || bytes.Equal(kindSafe, safe) {
		t.Fatal("scalar kinds collapsed")
	}
}

// RK-06: fresh exact policy match and non-forgeable owner attributes.
func TestRequestKeyAuthorizationExactAndOwned(t *testing.T) {
	scope := RequestKeyScope{TenantID: "t", ActorID: "a", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.otp.send"}
	caller := requestKeyUnitCaller(scope)
	caller.Request.Resource.Attributes = authorization.Attributes{"identity.request.method": authorization.StringValue("DELETE"), "identity.request.admission": authorization.BoolValue(false), "identity.command.recovery": authorization.BoolValue(true)}
	seen := false
	config := RequestKeyConfig{Namespace: "fixed", lookupKey: func() [32]byte { return [32]byte{1} }, Policy: CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(ctx context.Context, got authorization.DecisionContext) (authorization.Decision, error) {
		seen = true
		method, _ := got.Request.Resource.Attributes["identity.request.method"].String()
		admitted, _ := got.Request.Resource.Attributes["identity.request.admission"].Bool()
		namespace, _ := got.Request.Resource.Attributes["identity.request.namespace"].String()
		if method != "POST" || !admitted || namespace != "fixed" || got.Request.Environment.Time.IsZero() {
			t.Error("caller overrode request policy fields")
		}
		if _, exists := got.Request.Resource.Attributes["identity.command.recovery"]; exists {
			t.Error("borrowed command recovery attributes")
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}}
	allowed, err := authorizeRequestKey(context.Background(), scope, caller, &config)
	if !allowed || err != nil || !seen {
		t.Fatal("exact caller denied")
	}
	method, _ := caller.Request.Resource.Attributes["identity.request.method"].String()
	if method != "DELETE" {
		t.Fatal("policy rewrote caller input")
	}
	for _, change := range []func(*authorization.DecisionContext){
		func(dc *authorization.DecisionContext) { dc.Request.Subject.ID = "other" },
		func(dc *authorization.DecisionContext) { dc.Request.Subject.Kind = authorization.SubjectAPIKey },
		func(dc *authorization.DecisionContext) { dc.Request.Tenant = "other" },
		func(dc *authorization.DecisionContext) { dc.Request.Action = "other" },
		func(dc *authorization.DecisionContext) { dc.Request.Resource.ID = "other" },
		func(dc *authorization.DecisionContext) { dc.Request.Resource.Type = "identity.user" },
		func(dc *authorization.DecisionContext) { dc.PolicyRevision++ },
	} {
		bad := caller.Clone()
		change(&bad)
		seen = false
		if allowed, err := authorizeRequestKey(context.Background(), scope, bad, &config); allowed || err != nil || seen {
			t.Fatal("mismatched caller reached policy or admission")
		}
	}
	for _, mode := range []string{"denied", "stale", "failure", "panic"} {
		config.Policy.Authorization = queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			switch mode {
			case "denied":
				return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
			case "stale":
				return authorization.Decision{Outcome: authorization.Allow, Revision: 8}, nil
			case "panic":
				panic("synthetic-private-policy")
			}
			return authorization.Decision{}, errors.New("synthetic-private-policy")
		})
		allowed, err := authorizeRequestKey(context.Background(), scope, caller, &config)
		if allowed || err != nil && strings.Contains(err.Error(), "synthetic-private-policy") {
			t.Fatal("failed policy admitted or leaked")
		}
		if (mode == "failure" || mode == "panic") && err == nil {
			t.Fatal("dependency failure treated as ordinary deny")
		}
	}
}

func TestRequestKeyConfigurationAndMigrationFailures(t *testing.T) {
	config := RequestKeyConfig{Namespace: "fixed", lookupKey: func() [32]byte { return [32]byte{1} }, Policy: CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{}, nil
	})}}
	if !validRequestKeyConfig(config) {
		t.Fatal("valid config rejected")
	}
	if owned, err := NewRequestKeyConfig(config.Namespace, config.lookupKey(), config.Policy); err != nil || !validRequestKeyConfig(owned) {
		t.Fatal("valid public construction rejected")
	}
	for _, change := range []func(*RequestKeyConfig){func(c *RequestKeyConfig) { c.Namespace = "" }, func(c *RequestKeyConfig) { c.lookupKey = func() [32]byte { return [32]byte{} } }, func(c *RequestKeyConfig) { c.Policy.PolicyVersion = 0 }, func(c *RequestKeyConfig) { c.Policy.Authorization = queryDecision(nil) }} {
		bad := config
		change(&bad)
		if validRequestKeyConfig(bad) {
			t.Fatal("invalid configuration accepted")
		}
		if owned, err := NewRequestKeyConfig(bad.Namespace, bad.lookupKey(), bad.Policy); err == nil || validRequestKeyConfig(owned) {
			t.Fatal("failed public construction returned usable configuration")
		}
	}
	if fmt.Sprintf("%#v", config) != "postgres.RequestKeyConfig(redacted)" {
		t.Fatal("key config diagnostic disclosure")
	}
	if b, err := config.MarshalJSON(); b != nil || err == nil {
		t.Fatal("key config serialization")
	}
	source := RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 10 || history[9].DownSQL() != "" {
		t.Fatal("unsafe migration history")
	}
	first := history[9]
	history[9] = history[0]
	again, err := source.Load(context.Background())
	if err != nil || again[9] != first {
		t.Fatal("caller changed retained migration")
	}
	for _, bad := range []RequestKeyMigrationSource{{}, {Base: MigrationSource{}, Version: 9}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid migration composition accepted")
		}
	}
	if h, err := source.Load(nil); err == nil || h != nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := source.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancelled history disclosed")
	}
}

func TestRequestKeyNestedDiagnostics(t *testing.T) {
	lookup := [32]byte{113, 114, 115, 116, 117, 118}
	policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{}, nil
	})}
	config, err := NewRequestKeyConfig("synthetic", lookup, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{struct{ config RequestKeyConfig }{config}, &struct{ config RequestKeyConfig }{config}, struct{ configs []RequestKeyConfig }{[]RequestKeyConfig{config}}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			if strings.Contains(fmt.Sprintf(verb, value), fmt.Sprintf(verb, lookup)) {
				t.Fatalf("private configuration disclosed lookup key through %s", verb)
			}
		}
	}
}

func requestKeyUnitCaller(s RequestKeyScope) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(s.ActorID), Kind: s.ActorKind}, Tenant: authorization.TenantID(s.TenantID), Action: authorization.Action(s.RouteID), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(s.RouteID)}}}
}
