package session_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Core preparation/reveal contract, not real target reauthentication or guest
// revocation. Those must be proven by the native executor before delivery.
func anonymousUpgradeIssuerFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, identity.Command, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	_, _, _, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	spec.Lookup, spec.Version, spec.FamilyVersion = session.TokenDigest{}, 1, 1
	spec.LastActivityAt = spec.IssuedAt
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version, vector.SessionFamily.Version = 1, 1
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	clock := &mutableIssueClock{now: spec.IssuedAt}
	executor := &issueExecutor{}
	issuer, err := session.NewAnonymousUpgradeSessionIssuer(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(spec)
	b.OperationID, b.SchemaID, b.RecordID, b.ActorID, b.ActorKind = "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1", "distinct-guest", identity.ActorID(spec.UserID), authorization.SubjectUser
	prepared, err := issuer.PrepareAnonymousUpgrade(b, spec, 7, clock.now.Add(20*time.Second))
	if err != nil {
		t.Fatal("upgrade session preparation", err)
	}
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	guestVersion := identity.FeatureField{Name: "anonymous.source-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}}
	targetToken, _ := session.NewToken(32)
	wire, _ := targetToken.Reveal()
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{guestVersion}}, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		original, record, version, until, ok := r.AnonymousUpgradeCommand()
		if !ok || original != command || version != 7 || !until.Equal(spec.IssuedAt.Add(20*time.Second)) {
			t.Fatal("original upgrade input lost")
		}
		if _, ok := r.Command(); ok {
			t.Fatal("upgrade became generic proof admission")
		}
		if _, ok := r.AuthenticatedProof(); ok {
			t.Fatal("upgrade fabricated authenticated proof")
		}
		if r.Validate(nil, clock.now) == nil {
			t.Fatal("structural upgrade passed proof-route validation")
		}
		return session.IssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "committed-upgrade-audit", Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: 7, AfterVersion: 8}}, Session: record}, nil
	}
	return issuer, prepared, command, executor, clock
}

func TestAnonymousUpgradeIssuerRequiresExactTransitionAndKnownNewCommit(t *testing.T) {
	issuer, prepared, command, _, _ := anonymousUpgradeIssuerFixture(t)
	if _, err := issuer.Issue(context.Background(), prepared); err == nil {
		t.Fatal("unbound upgrade issued")
	}
	if _, ok := prepared.Request(); ok {
		t.Fatal("upgrade input advertised as proof-route recovery")
	}
	bound, err := issuer.BindAnonymousUpgrade(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.BindAnonymousUpgrade(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
		t.Fatal("upgrade bound twice", err)
	}
	out, err := issuer.Issue(context.Background(), bound)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
		t.Fatal("known new upgrade withheld", err)
	}
	original, _ := prepared.Session()
	want, _ := original.Bindings()
	got, _ := out.Session.Bindings()
	if got.UserID != want.UserID || got.Authentication != want.Authentication || got.Remember != want.Remember || got.Lookup != want.Lookup {
		t.Fatal("upgrade rewrote original authentication/remember/session custody")
	}
	if token, err := out.Token.Reveal(); err != nil || token == "" {
		t.Fatal("committed successor missing", err)
	}
	if out, err := issuer.Issue(context.Background(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
		t.Fatal("upgrade issue repeated", err)
	} else {
		requireNoIssuedToken(t, out)
	}
}

func TestAnonymousUpgradeIssuerWithholdsReplayUnknownWrongVersionAndLateDelivery(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "error", "wrong-before", "wrong-after", "wrong-target", "late", "backward"} {
		t.Run(mode, func(t *testing.T) {
			issuer, prepared, command, executor, clock := anonymousUpgradeIssuerFixture(t)
			native := executor.execute
			executor.execute = func(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				e, err := native(ctx, r)
				switch mode {
				case "replay":
					e.Replayed = true
				case "unknown":
					e.Receipt.Outcome, e.Receipt.AuditEventID, e.Receipt.Feature.BeforeVersion, e.Receipt.Feature.AfterVersion, e.Session = identity.CommitOutcomeUnknown, "", 0, 0, session.Session{}
				case "error":
					err = errors.New("private-upgrade-detail")
				case "wrong-before":
					e.Receipt.Feature.BeforeVersion--
				case "wrong-after":
					e.Receipt.Feature.AfterVersion++
				case "wrong-target":
					s, _ := e.Session.Bindings()
					s.UserID = "different"
					e.Session, _ = session.NewSession(s)
				case "late":
					clock.now = clock.now.Add(20 * time.Second)
				case "backward":
					clock.now = clock.now.Add(-time.Nanosecond)
				}
				return e, err
			}
			bound, err := issuer.BindAnonymousUpgrade(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			out, err := issuer.Issue(context.Background(), bound)
			if mode != "replay" && err == nil {
				t.Fatal("invalid upgrade result accepted")
			}
			requireNoIssuedToken(t, out)
		})
	}
}

func TestAnonymousUpgradeIssuerRejectsGuestTargetAndSourceVersionSubstitution(t *testing.T) {
	issuer, prepared, command, _, _ := anonymousUpgradeIssuerFixture(t)
	f, _ := command.Feature()
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(f *identity.FeatureCommandSpec) { f.Binding.RecordID = string(f.Binding.UserID) },
		func(f *identity.FeatureCommandSpec) { f.Binding.ActorID = identity.ActorID(f.Binding.RecordID) },
		func(f *identity.FeatureCommandSpec) { f.Binding.TenantID = "other" },
		func(f *identity.FeatureCommandSpec) { f.Fields[0].Value.Uint64++ },
		func(f *identity.FeatureCommandSpec) { f.Fields = nil },
	} {
		other := f
		other.Fields = append([]identity.FeatureField(nil), f.Fields...)
		change(&other)
		token, _ := command.SessionToken()
		candidate, err := identity.NewFeatureSessionCommand(other, token)
		if err != nil {
			continue
		}
		if _, err := issuer.BindAnonymousUpgrade(prepared, candidate); err == nil {
			t.Fatal("substituted upgrade bound")
		}
	}
	reconstructed, _ := identity.NewFeatureCommand(f)
	if _, err := issuer.BindAnonymousUpgrade(prepared, reconstructed); err == nil {
		t.Fatal("missing target credential bound")
	}
	record, _ := prepared.Session()
	spec, _ := record.Bindings()
	spec.Lookup = session.TokenDigest{}
	for _, before := range []uint64{0, ^uint64(0)} {
		if _, err := issuer.PrepareAnonymousUpgrade(f.Binding, spec, before, spec.IssuedAt.Add(20*time.Second)); err == nil {
			t.Fatal("invalid source version accepted")
		}
	}
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
	if _, err := issuer.PrepareAnonymousUpgrade(f.Binding, spec, 7, spec.IssuedAt.Add(20*time.Second)); err == nil {
		t.Fatal("guest became permanent target")
	}
}
