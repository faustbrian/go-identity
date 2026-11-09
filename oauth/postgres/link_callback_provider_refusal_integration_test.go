//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Refusal responses contain no identity token. This rejecting key set makes an
// accidental attempt to treat one as successful identity evidence fail closed.
type refusalRejectingKeySet struct{}

func (refusalRejectingKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// This exercises the native generation boundary with real HTTPS, PKCE custody
// and primary time. It is not coordinator reservation or full Reference proof.
func providerRefusalGenerationFixture(t *testing.T, response string) (context.Context, *rpLinkPhase, identity.Command, *atomic.Int32) {
	t.Helper()
	ctx, start, _, _, request, _, _ := storedRPCallbackFixture(t, 0)
	flow, err := start.service.loadRPLinkCallback(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(flow.destroy)
	calls := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	profile := flow.binding.Provider
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: profile.ID, Version: profile.Version, Issuer: profile.Issuer,
		AuthorizationEndpoint: profile.AuthorizationEndpoint, TokenEndpoint: server.URL + "/token",
		RedirectURI: profile.RedirectURI, ClientID: profile.ClientID,
		ClientAuthentication: profile.ClientAuthentication, Scopes: profile.Scopes,
		Algorithms: profile.Algorithms, KeySet: refusalRejectingKeySet{}, HTTPClient: server.Client(),
		Timeout: profile.Timeout, ClockSkew: profile.ClockSkew,
		MaxResponseBytes: profile.MaxResponseBytes, MaxTokenBytes: profile.MaxTokenBytes, MaxCodeBytes: profile.MaxCodeBytes,
	})
	if err != nil {
		t.Fatal("configure trusted refusal endpoint", err)
	}
	t.Cleanup(provider.Close)
	s := start.service
	s.providers, err = oauth.NewProviderRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	// The endpoint is trusted fixture configuration. It is not a callback input
	// or an override accepted by the production callback loader.
	flow.binding.Provider = provider.Profile()
	s.profiles[profile.ID] = flow.binding.Provider
	c := s.config()
	c.IntentKey = [32]byte{31}
	c.Session.Profile = sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "global", PolicyNamespace: "identity", Audience: "identity", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	s.config = func() LinkServiceConfig { return c }
	setRefusalFixtureSessionAuthority(t, &flow, c.Session.Profile)
	spec, err := callbackSpecification(flow)
	if err != nil {
		t.Fatal(err)
	}
	spec.Counters = identity.AccountLinkCounterContext{Network: request.Network, PreparedAt: start.input.Started, KeyVersions: []uint32{1}}
	input, ok := request.Callback.Input()
	if !ok {
		t.Fatal("missing original callback input")
	}
	original, err := identity.NewAccountLinkPreparationCommand(spec, input, request.Session)
	if err != nil {
		t.Fatal(err)
	}
	phase := &rpLinkPhase{service: s, flow: flow, original: original, declaration: kernel.CommandPlan{AccountLinkState: &flow.statePlan}}
	phase.input, err = phase.inputDigest(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(c.Session.Profile, flow.original, spec.Binding); err != nil {
		t.Fatal("fixture lacks original session authority", err)
	}
	return ctx, phase, original, calls
}

func setRefusalFixtureSessionAuthority(t *testing.T, flow *rpCallbackFlow, profile sessionpg.IdentifierAdmissionConfig) {
	t.Helper()
	spec, err := flow.original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: spec.TenantID}, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessionpg.SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := (authority.AuthorityScope{TenantID: authorization.TenantID(spec.TenantID), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(spec.UserID)}).Key()
	if err != nil {
		t.Fatal(err)
	}
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	spec.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding(keys.Global), Tenant: binding(keys.Tenant), User: binding(keys.User), Identifier: binding(keys.Identifier), Credential: binding(keys.Credential), SessionFamily: binding(sessions.Family), Session: binding(sessions.Session), Authorization: binding(policy)})
	if err != nil {
		t.Fatal(err)
	}
	flow.original, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	flow.binding.Input.Session, err = sessionpg.OriginalSessionFields(flow.original)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRPTokenEndpointRefusalProducesRetainableOutputWithoutGrant(t *testing.T) {
	ctx, phase, original, calls := providerRefusalGenerationFixture(t, `{"error":"invalid_grant"}`)
	wire, err := phase.GenerateAccountLinkPreparation(ctx, original, 3)
	if calls.Load() != 1 {
		t.Fatal("fixture did not reach exactly one real HTTPS exchange")
	}
	if err != nil || len(wire) == 0 {
		t.Fatalf("definitive refusal was discarded instead of sealed for journal retention: output=%d error=%T", len(wire), err)
	}
	command, _, issuance, err := phase.RestoreAccountLinkPreparation(ctx, original, 3, wire)
	if err == nil || !reflect.DeepEqual(command, identity.Command{}) || len(issuance.Grants) != 0 {
		t.Fatal("refusal restored a final executable command or grant")
	}
	if calls.Load() != 1 {
		t.Fatal("refusal restoration resubmitted original code")
	}
}

func TestRPAmbiguousTokenResponseNeverProducesDefinitiveRefusalOutput(t *testing.T) {
	ctx, phase, original, calls := providerRefusalGenerationFixture(t, `{"error":`)
	wire, err := phase.GenerateAccountLinkPreparation(ctx, original, 1)
	var failure *oauth.Error
	if calls.Load() != 1 || len(wire) != 0 || !errors.As(err, &failure) || failure.Kind() != oauth.Unknown {
		t.Fatalf("ambiguous response became retainable refusal: output=%d error=%T", len(wire), err)
	}
}

func TestRPProviderRefusalDecoderBindsOriginalInputStateAndGenerationWithoutHistoricalGrant(t *testing.T) {
	ctx, phase, original, calls := providerRefusalGenerationFixture(t, `{"error":"invalid_grant"}`)
	wire, err := phase.GenerateAccountLinkPreparation(ctx, original, 7)
	if err != nil || len(wire) == 0 {
		t.Fatal("definitive refusal was not retained", err)
	}
	decoder, ok := any(phase).(kernel.AccountLinkPreparationRefusalContributor)
	if !ok {
		t.Fatal("native owner has no typed refusal decoder")
	}
	spec, _, _, _ := original.AccountLinkPreparationInput()
	state := phase.flow.statePlan
	refusal, err := decoder.RestoreAccountLinkPreparationRefusal(ctx, spec.Binding, state, 7, wire)
	if err != nil || refusal.Binding != spec.Binding || refusal.State != state || refusal.Generation != 7 {
		t.Fatal("exact retained refusal did not authenticate", err)
	}
	for _, mode := range []string{"binding", "state", "generation", "input", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			copy := *phase
			b, proof, generation, output := spec.Binding, state, uint64(7), bytes.Clone(wire)
			switch mode {
			case "binding":
				b.RecordID = "other-account"
			case "state":
				proof.ProofFingerprint[0]++
			case "generation":
				generation++
			case "input":
				copy.input[0]++
			case "ciphertext":
				output[len(output)-1] ^= 1
			}
			wrong := any(&copy).(kernel.AccountLinkPreparationRefusalContributor)
			got, err := wrong.RestoreAccountLinkPreparationRefusal(ctx, b, proof, generation, output)
			if err == nil || got != (kernel.AccountLinkPreparationRefusal{}) {
				t.Fatal("substituted refusal acquired terminal evidence")
			}
		})
	}
	// Expired historical metadata cannot restore the ordinary Grant/checkpoint.
	// The typed refusal must authenticate without needing that execution path.
	historical := &rpLinkPhase{service: phase.service, flow: phase.flow}
	historical.flow.loadedAt = phase.flow.binding.ExpiresAt.Add(time.Second)
	historical.flow.stateGrant = capability.Grant{}
	historical.flow.stateProof = capability.Proof{}
	historical.flow.pkce = rpSealedVerifier{}
	_, input, _, _ := original.AccountLinkPreparationInput()
	input.Destroy()
	if historical.requireFresh(historical.flow.loadedAt) == nil {
		t.Fatal("historical fixture accidentally retained execution freshness")
	}
	got, err := any(historical).(kernel.AccountLinkPreparationRefusalContributor).RestoreAccountLinkPreparationRefusal(ctx, spec.Binding, state, 7, wire)
	if err != nil || got != refusal || calls.Load() != 1 {
		t.Fatal("historical refusal needed callback custody, restored a grant or re-exchanged", err)
	}
}
