package postgres

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Recovery must dispose of attached known output through the root journal;
// making the issuer's ordinary checkpoint restoration ignore expiry would
// recreate executable authority and is not a valid recovery implementation.
func TestRPExpiredRetainedLinkOutputCannotRestoreExecutionAuthority(t *testing.T) {
	start, retained, request, now := rpCallbackInputFixture(t)
	s := start.service
	c := s.config()
	c.Schema, c.IntentKey = "oauth_rp", [32]byte{31}
	s.config = func() LinkServiceConfig { return c }
	flow, err := s.authenticateRPCallback(t.Context(), request, retained.Binding, retained.StateProofCiphertext, *now)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.destroy()
	flow.loadedAt = *now
	spec, err := callbackSpecification(flow)
	if err != nil {
		t.Fatal(err)
	}
	spec.Counters = identity.AccountLinkCounterContext{Network: request.Network, PreparedAt: start.input.Started, KeyVersions: []uint32{1}}
	input, ok := request.Callback.Input()
	if !ok {
		t.Fatal("missing callback custody")
	}
	original, err := identity.NewAccountLinkPreparationCommand(spec, input, request.Session)
	if err != nil {
		t.Fatal(err)
	}
	phase := &rpLinkPhase{service: s, flow: flow, original: original}
	phase.input, err = phase.inputDigest(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	phase.declaration = kernel.CommandPlan{AccountLinkState: &flow.statePlan}
	account := identity.Account{ID: identity.AccountID(spec.Binding.RecordID), TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Provider: spec.ProviderID, Issuer: flow.binding.Provider.Issuer, Subject: "provider-subject", Version: 1}
	change := identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: account, ExpectedUserVersion: 3, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 2, Method: &identity.LoginMethod{Credential: identity.CredentialRef{ID: identity.CredentialID(account.ID), TenantID: account.TenantID, UserID: account.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: account.ID, Usable: true}}
	tokens, _ := rpVaultTokens(t, false, []string{"openid"})
	vault, err := s.sealProviderTokens(t.Context(), rpTokenVaultBinding{TenantID: account.TenantID, UserID: account.UserID, AccountID: account.ID, ProviderID: account.Provider, Issuer: account.Issuer, ClientID: flow.binding.Provider.ClientID, ConfigurationVersion: flow.binding.Provider.Version, AccountVersion: 1, SocialLinkVersion: 2}, tokens)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := identity.AccountLinkCommand{Binding: spec.Binding, Change: change, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion}
	wire, err := phase.sealLinkedOutput(t.Context(), original, 1, unsigned, vault, *now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("retain actual final issuance", err)
	}
	before := bytes.Clone(wire)
	out, restored, issuance, err := phase.restoreLinkedOutput(t.Context(), original, 1, wire)
	if err != nil {
		t.Fatal("live positive control failed", err)
	}
	linked, _, ok := restored.AccountLinkCounterCommand()
	if !ok || len(issuance.Grants) != 1 || !linked.Proof.Payload().ExpiresAt.Equal(flow.loadedAt.Add(20*time.Second)) {
		t.Fatal("fixture lost original final-grant lifetime")
	}
	*now = linked.Proof.Payload().ExpiresAt
	if !now.Before(flow.binding.ExpiresAt) || !now.Before(out.SourceExpiresAt) {
		t.Fatal("fixture did not retain valid original RP/provider evidence")
	}
	for _, loadedAt := range []time.Time{flow.loadedAt, *now} {
		phase.flow.loadedAt = loadedAt
		if _, command, plan, err := phase.restoreLinkedOutput(t.Context(), original, 1, wire); err == nil || !reflect.DeepEqual(command, identity.Command{}) || !reflect.DeepEqual(plan, kernel.CapabilityIssuancePlan{}) {
			t.Fatal("expired retained checkpoint restored or renewed executable authority")
		}
	}
	if !bytes.Equal(wire, before) || !linked.Proof.Payload().ExpiresAt.Equal(issuance.Grants[0].ExpiresAt) || out.ReadBegan != flow.loadedAt {
		t.Fatal("failed restoration replaced retained output or original timestamps")
	}
}
