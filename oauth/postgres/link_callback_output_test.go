package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// These are local encrypted output/issuer-contract checks. Account versions are
// structural fixtures, not current primary authority or a business-flow pass.
func TestRPLinkedOutputRestoresActualGrantWithoutRenewingOriginalEvidence(t *testing.T) {
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
		t.Fatal("missing callback")
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
	admitted := phase.declaration
	admitted.Digest = [32]byte{1}
	if err := phase.ValidateAccountLinkPreparation(original, admitted); err != nil {
		t.Fatal("kernel-computed plan digest changed native intent", err)
	}
	foreign := flow.statePlan
	foreign.Purpose = "other"
	admitted.AccountLinkState = &foreign
	if err := phase.ValidateAccountLinkPreparation(original, admitted); err == nil {
		t.Fatal("changed original state plan accepted")
	}
	account := identity.Account{ID: identity.AccountID(spec.Binding.RecordID), TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Provider: spec.ProviderID, Issuer: flow.binding.Provider.Issuer, Subject: "provider-subject", Version: 1}
	change := identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: account, ExpectedUserVersion: 3, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 2, Method: &identity.LoginMethod{Credential: identity.CredentialRef{ID: identity.CredentialID(account.ID), TenantID: account.TenantID, UserID: account.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: account.ID, Usable: true}}
	tokens, _ := rpVaultTokens(t, false, []string{"openid"})
	vault, err := s.sealProviderTokens(t.Context(), rpTokenVaultBinding{TenantID: account.TenantID, UserID: account.UserID, AccountID: account.ID, ProviderID: account.Provider, Issuer: account.Issuer, ClientID: flow.binding.Provider.ClientID, ConfigurationVersion: flow.binding.Provider.Version, AccountVersion: 1, SocialLinkVersion: 2}, tokens)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := identity.AccountLinkCommand{Binding: spec.Binding, Change: change, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion}
	wire, err := phase.sealLinkedOutput(t.Context(), original, 3, unsigned, vault, *now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("actual link issuance could not be retained", err)
	}
	*now = now.Add(5 * time.Second)
	out, restored, plan, err := phase.restoreLinkedOutput(t.Context(), original, 3, wire)
	if err != nil {
		t.Fatal("retained actual grant could not be restored", err)
	}
	linked, counters, ok := restored.AccountLinkCounterCommand()
	if !ok || linked.Binding != spec.Binding || linked.SessionID != spec.SessionID || linked.SessionVersion != spec.SessionVersion || !reflect.DeepEqual(linked.Change, change) || !reflect.DeepEqual(counters, spec.Counters) || linked.Proof.EnvelopeDigest() != plan.Grants[0].ProofFingerprint || !linked.Proof.Payload().ExpiresAt.Equal(flow.loadedAt.Add(20*time.Second)) || out.ReadBegan != flow.loadedAt || out.Tokens.AccessExpiresAt != vault.AccessExpiresAt {
		t.Fatal("restoration replaced original proof, time, token or counter intent")
	}
	if linked.Proof.EnvelopeDigest() == flow.statePlan.ProofFingerprint {
		t.Fatal("original state was substituted for the final account-link grant")
	}
	for name, mutate := range map[string]func(*identity.AccountLinkPreparationCommand){
		"account": func(s *identity.AccountLinkPreparationCommand) { s.Binding.RecordID = "other" },
		"counter": func(s *identity.AccountLinkPreparationCommand) {
			s.Counters.PreparedAt = s.Counters.PreparedAt.Add(time.Microsecond)
		},
		"network":  func(s *identity.AccountLinkPreparationCommand) { s.Counters.Network = "192.0.2.99" },
		"provider": func(s *identity.AccountLinkPreparationCommand) { s.ProviderConfigVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := spec
			mutate(&wrong)
			foreign, err := identity.NewAccountLinkPreparationCommand(wrong, input, request.Session)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := phase.restoreLinkedOutput(context.Background(), foreign, 3, wire); err == nil {
				t.Fatal("retained output accepted changed original input")
			}
		})
	}
	if _, _, _, err := phase.restoreLinkedOutput(t.Context(), original, 4, wire); err == nil {
		t.Fatal("output accepted another journal generation")
	}
	if _, _, _, err := phase.restoreLinkedOutput(t.Context(), original, 3, append([]byte(nil), wire[:len(wire)-1]...)); err == nil {
		t.Fatal("truncated output accepted")
	}
	input.Destroy()
	if _, _, _, err := phase.restoreLinkedOutput(t.Context(), original, 3, wire); err == nil {
		t.Fatal("destroyed original callback custody restored retained output")
	}
}
