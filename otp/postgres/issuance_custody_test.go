package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func issuanceCustodyFixture(t *testing.T, authenticated bool) (*AttemptCodec, otp.Challenge, identity.FeatureCommandSpec, auth.BearerCredential, AttemptAuthority) {
	t.Helper()
	var codec *AttemptCodec
	var command identity.Command
	var authority AttemptAuthority
	if authenticated {
		config, old, _, _ := nativeSessionFixture(t)
		codec, command = config.Codec, old
	} else {
		contributor, old, _ := nativeContributorFixture(t)
		codec, command = contributor.codec, old
	}
	spec, _ := command.Feature()
	authority, err := codec.restoreAuthority(spec)
	if err != nil {
		t.Fatal(err)
	}
	record, err := codec.restoreRecord(spec)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := record.Attempt.Continuation.Bindings()
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: b.Scope.Purpose, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	code, _ := command.OneTimeCode()
	scope, _ := record.Attempt.Continuation.DigestScope()
	digest, err := codec.verifier.Digest(scope, code)
	if err != nil {
		t.Fatal(err)
	}
	stored := digest.Storage()
	now := time.Now().UTC().Truncate(time.Microsecond)
	draft, err := otp.NewChallenge(otp.ChallengeSpec{Continuation: record.Attempt.Continuation, Policy: policy, Digest: stored, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), State: otp.ChallengeIssued, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	spec.Operation = issuanceOperation(spec.Operation.SubjectRequirement)
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
	spec.Binding.RecordID = b.Scope.ChallengeID
	spec.Fields = nil
	if authenticated {
		bearer, _ := command.SessionToken()
		return codec, draft, spec, bearer, authority
	}
	bearer, _ := command.PreAuthCookie()
	return codec, draft, spec, bearer, authority
}

func TestIssuanceCustodySurvivesRestartWithoutCode(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		codec, draft, spec, bearer, original := issuanceCustodyFixture(t, authenticated)
		mapCommand := codec.MapIssuancePreAuth
		if authenticated {
			mapCommand = codec.MapIssuanceSession
		}
		command, err := mapCommand(context.Background(), draft, spec, bearer, original)
		if err != nil {
			t.Fatal(err)
		}
		if _, present := command.OneTimeCode(); present {
			t.Fatal("issuance manufactured submitted-code custody")
		}
		if _, present := command.PreAuthCookie(); present == authenticated {
			t.Fatal("pre-auth custody crossed authorization variant")
		}
		if _, present := command.SessionToken(); present != authenticated {
			t.Fatal("session custody crossed authorization variant")
		}
		metadata, _ := command.Feature()
		restarted, _ := NewAttemptCodec(codecConfig())
		got, err := restarted.restoreIssuance(metadata)
		if err != nil || got.authority != original {
			t.Fatal("original issuance authority lost", err)
		}
		want, _ := draft.Bindings()
		actual, _ := got.challenge.Bindings()
		wc, _ := want.Continuation.Bindings()
		gc, _ := actual.Continuation.Bindings()
		if actual.Policy != want.Policy || actual.Digest != want.Digest || !actual.IssuedAt.Equal(want.IssuedAt) || !actual.ExpiresAt.Equal(want.ExpiresAt) || actual.State != want.State || actual.Version != want.Version || actual.UsedAttempts != 0 || actual.FailedAttempts != 0 || actual.Checks != 0 || gc.Scope != wc.Scope || gc.RememberPolicy != wc.RememberPolicy {
			t.Fatal("original challenge intent changed")
		}
		if authenticated {
			w, _ := wc.Authorization.AuthenticatedSession()
			g, _ := gc.Authorization.AuthenticatedSession()
			if !bytes.Equal(appendSessionRecord(nil, w), appendSessionRecord(nil, g)) {
				t.Fatal("original session changed")
			}
		} else {
			w, _ := wc.Authorization.PreAuthTransaction()
			g, _ := gc.Authorization.PreAuthTransaction()
			ws, _ := w.Bindings()
			gs, _ := g.Bindings()
			if ws != gs {
				t.Fatal("original pre-auth changed")
			}
		}
		if _, err := restarted.restoreRecord(metadata); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("issuance entered submitted-attempt protocol")
		}
		for _, change := range []func(*identity.FeatureCommandSpec){
			func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = "AgICAgICAgICAgICAgICAg" },
			func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other" },
			func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other" },
			func(s *identity.FeatureCommandSpec) {
				for i := range s.Fields {
					if s.Fields[i].Name == "otp.issue-custody" {
						s.Fields[i].Value.Bytes[0] ^= 1
					}
				}
			},
			func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
		} {
			x, _ := command.Feature()
			change(&x)
			if _, err := restarted.restoreIssuance(x); !errors.Is(err, ErrInvalidCommand) {
				t.Fatal("changed issuance intent accepted")
			}
		}
		for _, f := range metadata.Fields {
			if bytes.Contains(f.Value.Bytes, []byte(bearer.Token())) {
				t.Fatal("bearer persisted in fields")
			}
		}
	}
}

func TestIssuanceMappingRejectsWrongProfiles(t *testing.T) {
	codec, draft, spec, bearer, original := issuanceCustodyFixture(t, false)
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Fields = []identity.FeatureField{{Name: "otp.issue-custody"}} },
	} {
		x := spec
		change(&x)
		if out, err := codec.MapIssuancePreAuth(context.Background(), draft, x, bearer, original); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("changed issue scope accepted")
		} else if _, ok := out.Feature(); ok {
			t.Fatal("failure returned command")
		}
	}
	if _, err := codec.MapIssuanceSession(context.Background(), draft, spec, bearer, original); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("pre-auth issue became session issue")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := codec.MapIssuancePreAuth(ctx, draft, spec, bearer, original); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, err := codec.MapIssuancePreAuth(nil, draft, spec, bearer, original); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil context accepted")
	}
	if _, err := codec.MapIssuancePreAuth(context.Background(), otp.Challenge{}, spec, bearer, original); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("zero challenge accepted")
	}
}

func TestIssuanceRequiresOriginalBearerPossession(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		codec, draft, spec, bearer, original := issuanceCustodyFixture(t, authenticated)
		var p *Contributor
		var err error
		mapCommand := codec.MapIssuancePreAuth
		if authenticated {
			config, _, _, _ := nativeSessionFixture(t)
			config.Codec = codec
			p, err = NewContributorWithSession(config.ContributorConfig, *config.Session)
			mapCommand = codec.MapIssuanceSession
		} else {
			p, _, _ = nativeContributorFixture(t)
			p.codec = codec
		}
		if err != nil {
			t.Fatal(err)
		}
		command, err := mapCommand(context.Background(), draft, spec, bearer, original)
		if err != nil {
			t.Fatal(err)
		}
		custody, flow, err := p.authenticateIssuance(context.Background(), command)
		if err != nil || custody.authority != original || (flow.session != (session.Session{})) != authenticated {
			t.Fatal("original bearer rejected", err)
		}
		metadata, _ := command.Feature()
		wrong := auth.NewBearerCredential("WVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVk")
		var bad, swapped identity.Command
		if authenticated {
			bad, err = identity.NewFeatureSessionCommand(metadata, wrong)
			swapped, _ = identity.NewFeaturePreAuthCommand(metadata, bearer)
		} else {
			bad, err = identity.NewFeaturePreAuthCommand(metadata, wrong)
			swapped, _ = identity.NewFeatureSessionCommand(metadata, bearer)
		}
		if err != nil {
			t.Fatal(err)
		}
		plain, _ := identity.NewFeatureCommand(metadata)
		for _, candidate := range []identity.Command{bad, swapped, plain, {}} {
			if _, _, err := p.authenticateIssuance(context.Background(), candidate); !errors.Is(err, ErrInvalidCommand) {
				t.Fatal("wrong/absent/swapped bearer admitted", err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := p.authenticateIssuance(ctx, command); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost", err)
		}
	}
}

func TestIssuanceCustodyRetainsExactNamedKeys(t *testing.T) {
	codec, draft, spec, bearer, original := issuanceCustodyFixture(t, false)
	command, err := codec.MapIssuancePreAuth(context.Background(), draft, spec, bearer, original)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := command.Feature()
	for _, change := range []func(*AttemptCodecConfig){
		func(c *AttemptCodecConfig) { key := c.CodeKeys[4]; key[0] ^= 1; c.CodeKeys[4] = key },
		func(c *AttemptCodecConfig) { c.WrappingKeys["wrap-1"][0] ^= 1 },
		func(c *AttemptCodecConfig) {
			c.CurrentWrappingKey = "wrap-2"
			c.WrappingKeys = map[string][]byte{"wrap-2": bytes.Repeat([]byte{0x22}, 32)}
		},
		func(c *AttemptCodecConfig) { c.CurrentCodeKeyVersion = 3; delete(c.CodeKeys, 4) },
	} {
		config := codecConfig()
		change(&config)
		other, err := NewAttemptCodec(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.restoreIssuance(metadata); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("retired/changed named keys admitted")
		}
	}
	config := codecConfig()
	config.CurrentWrappingKey = "wrap-2"
	config.WrappingKeys["wrap-2"] = bytes.Repeat([]byte{0x22}, 32)
	config.CurrentCodeKeyVersion = 3
	rotated, err := NewAttemptCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.restoreIssuance(metadata); err != nil {
		t.Fatal("rotation changed retained custody", err)
	}
	for _, name := range []string{"otp.digest-key-version", "otp.unknown"} {
		x, _ := command.Feature()
		if name == "otp.unknown" {
			x.Fields = append(x.Fields, identity.FeatureField{Name: name})
		} else {
			for i := range x.Fields {
				if x.Fields[i].Name == name {
					x.Fields[i].Value.Uint64 = 3
				}
			}
		}
		if _, err := rotated.restoreIssuance(x); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("changed digest version/vocabulary admitted")
		}
	}
}
