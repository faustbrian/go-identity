package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func codecConfig() AttemptCodecConfig {
	return AttemptCodecConfig{WrappingKeys: map[string][]byte{"wrap-1": bytes.Repeat([]byte{0x21}, 32)}, CurrentWrappingKey: "wrap-1",
		AttemptKeys: map[uint32][32]byte{7: {0x31}}, CodeKeys: map[uint32][32]byte{3: {0x41}, 4: {0x42}}, CurrentCodeKeyVersion: 4, MaximumDuration: time.Second}
}

func TestAuthenticatedSessionCheckCustody(t *testing.T) {
	codec, err := NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	original, spec := mappedAttempt(t, otp.PurposeEmailVerification, false)
	bindings, _ := original.Bindings()
	continuationBindings, _ := bindings.Continuation.Bindings()
	continuationBindings.Scope.AuthorizationBinding = [32]byte{}
	flow, err := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "original-session"})
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := otp.NewContinuation(continuationBindings.Scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := original.Code()
	attempt, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeCheck, 13, code)
	if err != nil {
		t.Fatal(err)
	}
	command, plan, err := codec.Map(context.Background(), attempt, 3, spec)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewAttemptCodec(codecConfig())
	restored, err := restarted.restoreAttempt(command, plan)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := attempt.Bindings()
	got, _ := restored.Bindings()
	x, _ := got.Continuation.Bindings()
	y, _ := x.Authorization.Bindings()
	_, rememberErr := x.RememberPolicy.Bindings()
	if plan.Mode != identitypostgres.OTPCheck || got.AttemptID != want.AttemptID || got.Fingerprint != want.Fingerprint || y.Kind != otp.FlowAuthorizationAuthenticatedSession || y.AuthenticatedSessionID != "original-session" || rememberErr == nil {
		t.Fatal("session check custody changed during restart")
	}
}

func TestAttemptMappingRejectsChangedCustody(t *testing.T) {
	c, _ := NewAttemptCodec(codecConfig())
	a, s := mappedAttempt(t, otp.PurposeSignin, false)
	command, plan, err := c.Map(context.Background(), a, 3, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Binding.PolicyVersion++ },
		func(s *identity.FeatureCommandSpec) { s.Binding.CorrelationID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "other" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "otp.unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[1]) },
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "otp.attempt-custody" {
					s.Fields[i].Value.Bytes[0] ^= 1
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "otp.digest-key-version" {
					s.Fields[i].Value.Uint64 = 4
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "otp.digest-key-version" {
					s.Fields[i].Value.Uint64 = 1 << 32
				}
			}
		},
	} {
		x, _ := command.Feature()
		change(&x)
		if _, err := c.restoreRecord(x); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("changed private declaration accepted")
		}
	}
	for _, change := range []func(*identitypostgres.OTPAttemptPlan){
		func(p *identitypostgres.OTPAttemptPlan) { p.AttemptID = "AgICAgICAgICAgICAgICAg" },
		func(p *identitypostgres.OTPAttemptPlan) { p.AttemptFingerprint[0] ^= 1 },
		func(p *identitypostgres.OTPAttemptPlan) { p.FingerprintKeyVersion++ },
		func(p *identitypostgres.OTPAttemptPlan) { p.ChallengeID = "other" },
		func(p *identitypostgres.OTPAttemptPlan) { p.ScopeDigest[0] ^= 1 },
		func(p *identitypostgres.OTPAttemptPlan) { p.DigestKeyVersion = 4 },
		func(p *identitypostgres.OTPAttemptPlan) { p.ExpectedVersion++ },
		func(p *identitypostgres.OTPAttemptPlan) { p.Mode = identitypostgres.OTPCheck },
	} {
		x := plan
		change(&x)
		if _, err := c.restoreAttempt(command, x); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("changed plan accepted")
		}
	}
	// A retained key is not permission to reinterpret the original command's
	// authenticated digest version. Altering both plan fields must still deny.
	alternate := plan
	alternate.DigestKeyVersion = 4
	bindings, _ := a.Bindings()
	scope, _ := bindings.Continuation.DigestScope()
	verifier, _ := otp.NewVerifier(4, codecConfig().CodeKeys)
	digest, _ := verifier.ScopeDigest(scope, 4)
	alternate.ScopeDigest = digest.Value
	if _, err := c.restoreAttempt(command, alternate); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("coupled digest key and scope substitution accepted")
	}
	wrong, _ := auth.NewOneTimeCode("654321")
	spec, _ := command.Feature()
	other, err := identity.NewFeatureOneTimeCodeCommand(spec, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.restoreAttempt(other, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("changed submitted code accepted")
	}
	plain, _ := identity.NewFeatureCommand(spec)
	if _, err := c.restoreAttempt(plain, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("absent submitted code accepted")
	}
	if _, err := c.restoreAttempt(identity.Command{}, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("zero command accepted")
	}
	for _, name := range []string{"otp", "otp.attempt-custody", "otp.other"} {
		x := s
		x.Fields = []identity.FeatureField{{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "collision"}}}
		if _, _, err := c.Map(context.Background(), a, 3, x); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("reserved namespace accepted")
		}
	}
	x := s
	x.Binding.ActorID = "other"
	if _, _, err := c.Map(context.Background(), a, 3, x); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("foreign mapping accepted")
	}
	if _, _, err := c.Map(context.Background(), a, 99, s); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("retired digest version remapped")
	}
	if _, _, err := c.Map(context.Background(), otp.AttemptCommand{}, 3, s); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("zero attempt mapped")
	}
	var nilCodec *AttemptCodec
	if _, _, err := nilCodec.Map(context.Background(), a, 3, s); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil codec mapped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.Map(ctx, a, 3, s); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled mapping succeeded")
	}
}

func TestAttemptCodecRetainedVersionsAndOwnedKeys(t *testing.T) {
	config := codecConfig()
	c, err := NewAttemptCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	a, s := mappedAttempt(t, otp.PurposeSignin, false)
	command, plan, err := c.Map(context.Background(), a, 3, s)
	if err != nil {
		t.Fatal(err)
	}
	clear(config.WrappingKeys["wrap-1"])
	delete(config.AttemptKeys, 7)
	delete(config.CodeKeys, 3)
	if _, err := c.restoreAttempt(command, plan); err != nil {
		t.Fatal("caller key mutation changed codec", err)
	}
	rotated := codecConfig()
	rotated.WrappingKeys["wrap-2"] = bytes.Repeat([]byte{0x22}, 32)
	rotated.CurrentWrappingKey = "wrap-2"
	other, err := NewAttemptCodec(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.restoreAttempt(command, plan); err != nil {
		t.Fatal("retained wrapping key failed", err)
	}
	for _, change := range []func(*AttemptCodecConfig){
		func(c *AttemptCodecConfig) {
			delete(c.WrappingKeys, "wrap-1")
			c.WrappingKeys["wrap-2"] = bytes.Repeat([]byte{0x22}, 32)
			c.CurrentWrappingKey = "wrap-2"
		},
		func(c *AttemptCodecConfig) { c.WrappingKeys["wrap-1"][0] ^= 1 },
		func(c *AttemptCodecConfig) { delete(c.AttemptKeys, 7); c.AttemptKeys[8] = [32]byte{0x32} },
		func(c *AttemptCodecConfig) { c.AttemptKeys[7] = [32]byte{0x32} },
		func(c *AttemptCodecConfig) { delete(c.CodeKeys, 3) },
		func(c *AttemptCodecConfig) { c.CodeKeys[3] = [32]byte{0x43} },
	} {
		cfg := codecConfig()
		change(&cfg)
		reader, err := NewAttemptCodec(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.restoreAttempt(command, plan); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("unavailable/replaced historical key accepted")
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 10 {
				if _, err := c.restoreAttempt(command, plan); err != nil {
					t.Error("concurrent restoration", err)
				}
			}
		})
	}
	wg.Wait()
	for _, value := range []any{codecConfig(), c} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if !strings.Contains(fmt.Sprintf(format, value), "redacted") {
				t.Fatal("private diagnostics not redacted")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, otp.ErrSensitiveSerialization) {
			t.Fatal("private JSON admitted")
		}
	}
}

func TestAttemptCodecConfigurationBounds(t *testing.T) {
	for _, change := range []func(*AttemptCodecConfig){
		func(c *AttemptCodecConfig) { c.WrappingKeys = nil },
		func(c *AttemptCodecConfig) { c.WrappingKeys["wrap-1"] = make([]byte, 32) },
		func(c *AttemptCodecConfig) { c.WrappingKeys["wrap-1"] = []byte{1} },
		func(c *AttemptCodecConfig) { c.CurrentWrappingKey = "missing" },
		func(c *AttemptCodecConfig) { c.WrappingKeys["bad ref"] = bytes.Repeat([]byte{1}, 32) },
		func(c *AttemptCodecConfig) { c.WrappingKeys[""] = bytes.Repeat([]byte{1}, 32) },
		func(c *AttemptCodecConfig) { c.WrappingKeys[strings.Repeat("a", 129)] = bytes.Repeat([]byte{1}, 32) },
		func(c *AttemptCodecConfig) {
			for i := range 9 {
				c.WrappingKeys[fmt.Sprint(i)] = bytes.Repeat([]byte{1}, 32)
			}
		},
		func(c *AttemptCodecConfig) { c.AttemptKeys = nil },
		func(c *AttemptCodecConfig) { c.AttemptKeys[0] = [32]byte{1} },
		func(c *AttemptCodecConfig) { c.AttemptKeys[7] = [32]byte{} },
		func(c *AttemptCodecConfig) {
			for i := range uint32(9) {
				c.AttemptKeys[i+1] = [32]byte{1}
			}
		},
		func(c *AttemptCodecConfig) { c.CodeKeys = nil },
		func(c *AttemptCodecConfig) { c.CurrentCodeKeyVersion = 0 },
		func(c *AttemptCodecConfig) { c.MaximumDuration = 0 },
		func(c *AttemptCodecConfig) { c.MaximumDuration = 6 * time.Second },
	} {
		cfg := codecConfig()
		change(&cfg)
		if c, err := NewAttemptCodec(cfg); c != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("unsafe key policy accepted")
		}
	}
}

func TestAttemptRecordLiteralProfile(t *testing.T) {
	a, s := mappedAttempt(t, otp.PurposeSignin, false)
	i, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	record, err := i.SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := a.Bindings()
	expected := []byte("identity-otp-attempt-custody-v1\x00")
	for _, v := range []string{string(b.AttemptID), string(b.Fingerprint), "tenant", "signin", "user", "email", "private-person@example.test", "challenge", "target"} {
		expected = binary.BigEndian.AppendUint16(expected, uint16(len(v)))
		expected = append(expected, v...)
	}
	expected = binary.BigEndian.AppendUint32(expected, 7)
	expected = append(expected, 2)
	for _, n := range []uint64{13, 11, 12} {
		expected = binary.BigEndian.AppendUint64(expected, n)
	}
	expected = append(expected, 2)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 22)
	expected = append(expected, "AgICAgICAgICAgICAgICAg"...)
	expected = append(expected, 1)
	for _, d := range []time.Duration{time.Hour + 1, 30*time.Minute + 1, time.Minute + 1, 15*time.Minute + 1} {
		expected = binary.BigEndian.AppendUint64(expected, uint64(d))
	}
	expected = append(expected, record.Signature[:]...)
	if !bytes.Equal(expected, encodeAttemptRecord(record)) {
		t.Fatal("private wire profile drift")
	}
	// Independently fixed structural AAD: every frozen binding/operation scalar
	// and the exact digest-key version is length-delimited/domain separated.
	frame := []byte("identity-otp-command-envelope-binding-v1\x00")
	for _, v := range []string{"AQEBAQEBAQEBAQEBAQEBAQ", "tenant", "user", "", "service", "service-account", "identity.otp.signin", "policy", "identity-otp-signin", "correlation", "target", "identity/otp", "identity.otp.signin", "identity-otp-signin"} {
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(v)))
		frame = append(frame, v...)
	}
	frame = binary.BigEndian.AppendUint64(frame, 1)
	frame = binary.BigEndian.AppendUint32(frame, 1)
	frame = append(frame, 0)
	frame = binary.BigEndian.AppendUint32(frame, 1)
	frame = append(frame, 2, 0)
	frame = binary.BigEndian.AppendUint32(frame, 3)
	digest := sha256.Sum256(frame)
	aad, err := attemptAAD(s, 3)
	if err != nil {
		t.Fatal(err)
	}
	values := aad.Values()
	if len(values) != 2 || values["profile"] != "identity-otp-command-custody-v1" || values["binding"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("AAD drift")
	}
	for n := range len(expected) {
		if _, err := decodeAttemptRecord(expected[:n], s.Binding, s.Operation); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("truncated record accepted")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(expected), 0), bytes.Repeat([]byte{1}, 4097), nil, []byte(recordPrefix)} {
		if _, err := decodeAttemptRecord(bad, s.Binding, s.Operation); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("hostile record accepted")
		}
	}
	oversized := bytes.Clone(expected)
	binary.BigEndian.PutUint16(oversized[len(recordPrefix):], 65535)
	if _, err := decodeAttemptRecord(oversized, s.Binding, s.Operation); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("oversized string admitted")
	}
}

func mappedAttempt(t testing.TB, purpose otp.Purpose, anonymous bool) (otp.AttemptCommand, identity.FeatureCommandSpec) {
	t.Helper()
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "user", ActorID: "service", ActorKind: "service-account", OperationID: op.OperationID, PolicyID: "policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "target"}
	if anonymous {
		b.UserID = ""
		b.AnonymousFlowID = "flow"
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	dest, err := otp.NewDestinationInput("private-person@example.test")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: "AgICAgICAgICAgICAgICAg"})
	if err != nil {
		t.Fatal(err)
	}
	var remember session.RememberPolicy
	if purpose == otp.PurposeSignin || purpose == otp.PurposeMFA {
		remember, err = session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour + time.Nanosecond, IdleTTL: 30*time.Minute + time.Nanosecond, RefreshAfter: time.Minute + time.Nanosecond, FreshFor: 15*time.Minute + time.Nanosecond})
		if err != nil {
			t.Fatal(err)
		}
	}
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: "tenant", Purpose: purpose, SubjectID: string(b.UserID), Channel: otp.ChannelEmail, Destination: dest, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 11, Generation: 12}, flow, remember)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := otp.NewAttemptIssuer(7, [32]byte{0x31})
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	a, err := issuer.PrepareForCommand(context.Background(), b, op, continuation, otp.AttemptModeConsume, 13, code)
	if err != nil {
		t.Fatal(err)
	}
	return a, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "feature.flag", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}}
}

func TestAttemptMappingRestoresOriginalCustody(t *testing.T) {
	c, err := NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []otp.Purpose{otp.PurposeSignin, otp.PurposeEmailVerification, otp.PurposeMFA} {
		for _, anonymous := range []bool{false, true} {
			a, s := mappedAttempt(t, purpose, anonymous)
			command, plan, err := c.Map(context.Background(), a, 3, s)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.restoreAttempt(command, plan)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := a.Bindings()
			restored, _ := got.Bindings()
			if original.CommandID != restored.CommandID || original.AttemptID != restored.AttemptID || original.Fingerprint != restored.Fingerprint || original.FingerprintKeyVersion != restored.FingerprintKeyVersion || original.Mode != restored.Mode || original.ExpectedVersion != restored.ExpectedVersion {
				t.Fatal("original attempt changed")
			}
			x, _ := original.Continuation.Bindings()
			y, _ := restored.Continuation.Bindings()
			if x.Scope != y.Scope || x.Authorization != y.Authorization || x.RememberPolicy != y.RememberPolicy {
				t.Fatal("continuation changed")
			}
			v, _ := otp.NewVerifier(4, codecConfig().CodeKeys)
			ds, _ := a.Bindings()
			scope, _ := ds.Continuation.DigestScope()
			want, _ := v.ScopeDigest(scope, 3)
			if plan.ScopeDigest != want.Value || plan.DigestKeyVersion != 3 || plan.AttemptID != string(original.AttemptID) {
				t.Fatal("retained scope version remapped")
			}
			spec, ok := command.Feature()
			if !ok || len(spec.Fields) != 3 || len(s.Fields) != 1 {
				t.Fatal("input mutated or fields replaced")
			}
			for _, f := range spec.Fields {
				if f.Value.Kind == identity.FeatureText || bytes.Contains(f.Value.Bytes, []byte("private-person@example.test")) {
					t.Fatal("plaintext destination escaped")
				}
			}
			// Code-free phase reconstruction retains original declaration, without
			// exposing an online comparison against stored challenge digests.
			record, err := c.restoreRecord(spec)
			if err != nil {
				t.Fatal(err)
			}
			if record.Attempt.AttemptID != original.AttemptID {
				t.Fatal("new recovery identity")
			}
		}
	}
	if _, _, err := c.Map(nil, otp.AttemptCommand{}, 3, identity.FeatureCommandSpec{}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil mapping accepted")
	}
}
