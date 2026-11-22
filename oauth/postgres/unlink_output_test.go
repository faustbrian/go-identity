package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestRPUnlinkOutputRestoresOnlyTheOriginalLiveGrant(t *testing.T) {
	phase, clock, _ := rpOutputFixture(t)
	s := phase.service
	c := s.config()
	c.Schema, c.ConfigurationID, c.IntentKey = "oauth_rp", "rp-test", [32]byte{31}
	s.config = func() LinkServiceConfig { return c }
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	issued := *clock
	*clock = issued.Add(250 * time.Millisecond)
	admitted := *clock
	deadline := issued.Add(9*time.Second + 500*time.Millisecond)
	spec := identity.AccountUnlinkPreparationCommand{
		Binding: identity.CommandBinding{
			CommandID: id, TenantID: "tenant", UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser,
			OperationID: "identity.account.unlink", SchemaID: "identity-account", SchemaVersion: 1,
			PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(id), RecordID: "social-account",
		},
		Change: identity.AccountUnlinkChange{
			TenantID: "tenant", UserID: "user", AccountID: "social-account",
			ExpectedUserVersion: 6, ExpectedAccountVersion: 2, ExpectedSocialLinkVersion: 3, ExpectedCredentialVersion: 4,
		},
		SessionID: "original-session", SessionVersion: 5, FactorAuthorityVersion: 7,
		Counters: identity.AccountUnlinkCounterContext{Network: "192.0.2.1", PreparedAt: issued, KeyVersions: []uint32{1}},
		Primary: auth.ReauthenticationProof{
			Proof: auth.Proof{ID: "original-password-proof", Tenant: "tenant", Subject: "user", Method: "password",
				Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "unlink-management",
				IssuedAt: issued, ExpiresAt: issued.Add(time.Minute)},
			SessionID: "original-session", SessionVersion: 5, Action: "identity.account.unlink",
		},
	}
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32)))
	preparation := func(spec identity.AccountUnlinkPreparationCommand, bearer auth.BearerCredential) identity.Command {
		t.Helper()
		command, err := identity.NewAccountUnlinkPreparationCommand(spec, bearer)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	original := preparation(spec, bearer)
	wire, err := s.sealUnlinkOutput(t.Context(), original, 3, admitted, deadline)
	if err != nil {
		t.Fatal("a new proof within this second cannot issue unlink", err)
	}
	resume := func(generation uint64) [32]byte {
		t.Helper()
		command, plan, err := s.restoreUnlinkOutput(t.Context(), original, generation, wire)
		if err != nil {
			t.Fatal("authentic retained unlink grant did not restore", err)
		}
		got, counters, ok := command.AccountUnlinkCounterCommand()
		grant := got.Proof.Payload()
		if !ok || got.Binding != spec.Binding || got.Change != spec.Change || got.SessionID != spec.SessionID || got.SessionVersion != spec.SessionVersion ||
			counters.PreparedAt != spec.Counters.PreparedAt || grant.Bearer || grant.MaxUses != 1 || !grant.IssuedAt.Equal(issued) || !grant.ExpiresAt.Equal(deadline.Truncate(time.Second)) ||
			len(plan.Grants) != 1 || plan.Grants[0].ProofFingerprint != got.Proof.EnvelopeDigest() {
			t.Fatal("restoration changed retained intent, proof identity, or lifetime")
		}
		return got.Proof.EnvelopeDigest()
	}
	first := resume(3)
	*clock = admitted.Add(3 * time.Second)
	if first != resume(3) {
		t.Fatal("retry reissued or replaced retained proof")
	}
	for name, change := range map[string]func(*identity.AccountUnlinkPreparationCommand){
		"ancestor proof":  func(s *identity.AccountUnlinkPreparationCommand) { s.Primary.Proof.ID = "a-different-password-proof" },
		"MFA generation":  func(s *identity.AccountUnlinkPreparationCommand) { s.FactorAuthorityVersion++ },
		"account version": func(s *identity.AccountUnlinkPreparationCommand) { s.Change.ExpectedAccountVersion++ },
		"network":         func(s *identity.AccountUnlinkPreparationCommand) { s.Counters.Network = "192.0.2.2" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := spec
			change(&changed)
			if _, _, err := s.restoreUnlinkOutput(t.Context(), preparation(changed, bearer), 3, wire); err == nil {
				t.Fatal("changed original restored retained grant")
			}
		})
	}
	otherBearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)))
	if _, _, err := s.restoreUnlinkOutput(t.Context(), preparation(spec, otherBearer), 3, wire); err == nil {
		t.Fatal("changed session possession restored retained grant")
	}
	if _, _, err := s.restoreUnlinkOutput(t.Context(), original, 4, wire); err == nil {
		t.Fatal("different journal generation restored retained grant")
	}
	if _, _, err := s.restoreUnlinkOutput(t.Context(), original, 3, wire[:len(wire)-1]); err == nil {
		t.Fatal("incomplete checkpoint restored retained grant")
	}
	*clock = deadline.Truncate(time.Second)
	if _, _, err := s.restoreUnlinkOutput(t.Context(), original, 3, wire); err == nil {
		t.Fatal("exclusive expiry restored executable grant")
	}
}
