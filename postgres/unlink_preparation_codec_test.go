package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func recordUnlinkPreparation(t *testing.T, change func(*identity.AccountUnlinkPreparationCommand), token byte) identity.Command {
	t.Helper()
	issued := recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, nil)
	spec, _ := issued.UnlinkAccount()
	now := time.Unix(1000, 123000).UTC()
	original := identity.AccountUnlinkPreparationCommand{
		Binding: spec.Binding, Change: spec.Change, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion,
		FactorAuthorityVersion: 7,
		Counters:               identity.AccountUnlinkCounterContext{Network: "192.0.2.55", PreparedAt: now, KeyVersions: []uint32{9, 7}},
		Primary: authentication.ReauthenticationProof{
			Proof:     authentication.Proof{ID: "original-password-proof", Tenant: string(spec.Binding.TenantID), Subject: string(spec.Binding.UserID), Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "backend", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
			SessionID: spec.SessionID, SessionVersion: spec.SessionVersion, Action: spec.Binding.OperationID,
		},
	}
	if change != nil {
		change(&original)
	}
	bearer := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{token}, 32)))
	command, err := identity.NewAccountUnlinkPreparationCommand(original, bearer)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestAccountUnlinkPreparationCodecBindsOriginalPrimarySessionAndIntent(t *testing.T) {
	command := recordUnlinkPreparation(t, nil, 1)
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal("native canonical codec rejects original typed unlink preparation", err)
	}
	original, bearer, _ := command.AccountUnlinkPreparationInput()
	for _, private := range []string{bearer.Token(), string(original.Primary.Proof.ID), original.Counters.Network} {
		if bytes.Contains(q.canonical, []byte(private)) || bytes.Contains(q.safeFields, []byte(private)) {
			t.Fatal("original private custody disclosed in canonical journal input")
		}
	}
	for _, change := range []func(*identity.AccountUnlinkPreparationCommand){
		func(s *identity.AccountUnlinkPreparationCommand) { s.Change.ExpectedUserVersion++ },
		func(s *identity.AccountUnlinkPreparationCommand) { s.Change.ExpectedAccountVersion++ },
		func(s *identity.AccountUnlinkPreparationCommand) { s.Change.ExpectedSocialLinkVersion++ },
		func(s *identity.AccountUnlinkPreparationCommand) { s.Change.ExpectedCredentialVersion++ },
		func(s *identity.AccountUnlinkPreparationCommand) { s.FactorAuthorityVersion++ },
		func(s *identity.AccountUnlinkPreparationCommand) { s.CSRFCommitment[0] = 1 },
		func(s *identity.AccountUnlinkPreparationCommand) { s.RevokeProvider = true },
		func(s *identity.AccountUnlinkPreparationCommand) { s.Primary.Proof.ID = "different-password-proof" },
		func(s *identity.AccountUnlinkPreparationCommand) { s.Primary.Proof.Audience = "different-audience" },
		func(s *identity.AccountUnlinkPreparationCommand) {
			s.Primary.Proof.IssuedAt = s.Primary.Proof.IssuedAt.Add(time.Nanosecond)
		},
		func(s *identity.AccountUnlinkPreparationCommand) {
			s.Primary.Proof.ExpiresAt = s.Primary.Proof.ExpiresAt.Add(time.Nanosecond)
		},
		func(s *identity.AccountUnlinkPreparationCommand) { s.Counters.Network = "192.0.2.99" },
		func(s *identity.AccountUnlinkPreparationCommand) {
			s.Counters.PreparedAt = s.Counters.PreparedAt.Add(time.Microsecond)
		},
		func(s *identity.AccountUnlinkPreparationCommand) { s.Counters.KeyVersions = []uint32{9} },
	} {
		other, err := prepareClaim(recordUnlinkPreparation(t, change, 1), [32]byte{1})
		if err != nil || bytes.Equal(other.canonical, q.canonical) || !bytes.Equal(other.safeFields, q.safeFields) {
			t.Fatal("original intent/primary/counters omitted from fingerprint or changed scope", err)
		}
	}
	otherSession, err := prepareClaim(recordUnlinkPreparation(t, nil, 2), [32]byte{1})
	if err != nil || bytes.Equal(otherSession.canonical, q.canonical) {
		t.Fatal("original bearer omitted from keyed preparation", err)
	}
	otherKey, err := prepareClaim(command, [32]byte{2})
	if err != nil || bytes.Equal(otherKey.canonical, q.canonical) {
		t.Fatal("original custody not bound to retained command key", err)
	}
	bare := encodedRecord(t, recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, nil))
	if bytes.Equal(bare.canonical, q.canonical) || !bytes.Equal(bare.safeFields, q.safeFields) {
		t.Fatal("original preparation confused with final issued unlink or changed final scope")
	}
	if capabilityReservationCommand(command, CommandPlan{}) {
		t.Fatal("encoding original input enabled grant-free execution")
	}
}
