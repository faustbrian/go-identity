package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
)

func unlinkPreparationFixture(t *testing.T) (AccountUnlinkPreparationCommand, authentication.BearerCredential) {
	t.Helper()
	original := unlinkCounterCommand(t)
	unlink, _ := original.UnlinkAccount()
	now := queryClock{}.Now()
	proof := authentication.ReauthenticationProof{
		Proof:     authentication.Proof{ID: "reauthentication-original", Tenant: string(unlink.Binding.TenantID), Subject: string(unlink.Binding.UserID), Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "identity-backend", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		SessionID: unlink.SessionID, SessionVersion: unlink.SessionVersion, Action: unlink.Binding.OperationID,
	}
	return AccountUnlinkPreparationCommand{
		Binding: unlink.Binding, Change: unlink.Change, SessionID: unlink.SessionID,
		SessionVersion: unlink.SessionVersion, RevokeProvider: unlink.RevokeProvider,
		FactorAuthorityVersion: 7,
		Counters:               AccountUnlinkCounterContext{Network: "192.0.2.55", PreparedAt: now, KeyVersions: []uint32{9, 7}},
		Primary:                proof,
	}, authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
}

func TestAccountUnlinkPreparationRetainsOriginalPrimaryAndSessionWithoutGrant(t *testing.T) {
	// Structural input is deliberately not proof authority. Native execution
	// must validate the actual signed password record and current session/factors.
	input, bearer := unlinkPreparationFixture(t)
	original := input
	original.Counters.KeyVersions = append([]uint32(nil), input.Counters.KeyVersions...)
	command, err := NewAccountUnlinkPreparationCommand(input, bearer)
	if err != nil {
		t.Fatal(err)
	}
	input.Counters.KeyVersions[0] = 100
	got, retainedBearer, ok := command.AccountUnlinkPreparationInput()
	if !ok || !reflect.DeepEqual(got, original) || retainedBearer.Token() != bearer.Token() {
		t.Fatal("original primary, exact intent, session or counter custody changed")
	}
	got.Counters.KeyVersions[0] = 200
	again, _, _ := command.AccountUnlinkPreparationInput()
	if again.Counters.KeyVersions[0] != 9 || again.Primary != original.Primary {
		t.Fatal("returned preparation input aliases retained state or renews proof")
	}
	if _, ok := command.UnlinkAccount(); ok {
		t.Fatal("preparation without canonical child grant can execute ordinary unlink")
	}
	if _, _, ok := command.AccountUnlinkCounterCommand(); ok {
		t.Fatal("preparation can bypass issuer attachment through decorated unlink")
	}
	if _, _, _, ok := command.AccountLinkPreparationInput(); ok {
		t.Fatal("unlink input is interpreted as an OAuth link callback")
	}
	if wire, err := json.Marshal(command); err == nil || len(wire) != 0 {
		t.Fatal("original preparation custody serialized")
	}
	if text := fmt.Sprintf("%#v", command); strings.Contains(text, bearer.Token()) || strings.Contains(text, string(original.Primary.Proof.ID)) {
		t.Fatal("original session or proof leaked through command diagnostics")
	}
}

func TestAccountUnlinkPreparationRejectsUnboundPrimaryAndMalformedSession(t *testing.T) {
	input, bearer := unlinkPreparationFixture(t)
	for _, change := range []func(*AccountUnlinkPreparationCommand){
		func(s *AccountUnlinkPreparationCommand) { s.Binding.OperationID = "identity.account.link-token" },
		func(s *AccountUnlinkPreparationCommand) { s.Change.AccountID = "different-account" },
		func(s *AccountUnlinkPreparationCommand) { s.Change.ExpectedCredentialVersion = 0 },
		func(s *AccountUnlinkPreparationCommand) { s.SessionID = "different-session" },
		func(s *AccountUnlinkPreparationCommand) { s.SessionVersion++ },
		func(s *AccountUnlinkPreparationCommand) { s.FactorAuthorityVersion = 0 },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.ID = "" },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.Tenant = "different-tenant" },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.Subject = "different-user" },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.Method = "totp" },
		func(s *AccountUnlinkPreparationCommand) {
			s.Primary.Proof.Assurance = authentication.AssuranceUnspecified
		},
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.Purpose = "different-purpose" },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.Audience = "" },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Proof.ExpiresAt = s.Primary.Proof.IssuedAt },
		func(s *AccountUnlinkPreparationCommand) { s.Primary.Action = "identity.password.change" },
		func(s *AccountUnlinkPreparationCommand) { s.Counters.KeyVersions = nil },
	} {
		candidate := input
		change(&candidate)
		if command, err := NewAccountUnlinkPreparationCommand(candidate, bearer); err == nil || !reflect.DeepEqual(command, Command{}) {
			t.Fatal("unbound preparation retained a partial command")
		}
	}
	for _, wire := range []string{"", "not-a-session", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 65)), bearer.Token() + "="} {
		if command, err := NewAccountUnlinkPreparationCommand(input, authentication.NewBearerCredential(wire)); err == nil || !reflect.DeepEqual(command, Command{}) {
			t.Fatal("malformed original session admitted")
		}
	}
	if _, _, ok := (Command{}).AccountUnlinkPreparationInput(); ok {
		t.Fatal("zero command exposed unlink preparation")
	}
	if _, _, ok := unlinkCounterCommand(t).AccountUnlinkPreparationInput(); ok {
		t.Fatal("ordinary issued unlink reinterpreted as preparation")
	}
}
