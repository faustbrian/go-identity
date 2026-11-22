package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestAccountUnlinkCountersRetainOriginalChargeScope(t *testing.T) {
	at := time.Date(2026, 11, 14, 8, 0, 0, 123000, time.UTC)
	spec, bearer, subject := unlinkCounterInput(t, at)
	oldKey, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	newKey, _ := risk.NewCounterDigestKey(9, bytes.Repeat([]byte{0x32}, 32))
	originalOwner, err := NewRepository(protectedConfig(t, oldKey))
	if err != nil {
		t.Fatal(err)
	}
	original, plan, err := originalOwner.PrepareAccountUnlinkPreparationCounters(spec, bearer, subject, at)
	if err != nil {
		t.Fatal("cannot prepare original unlink counters:", err)
	}
	snapshot, _, ok := original.AccountUnlinkPreparationInput()
	if !ok || snapshot.Binding != spec.Binding || snapshot.Primary != spec.Primary || snapshot.Counters.Network != subject.Network || snapshot.Counters.PreparedAt != at || len(snapshot.Counters.KeyVersions) != 1 || snapshot.Counters.KeyVersions[0] != 7 {
		t.Fatal("counter preparation changed proof metadata, scope or original time")
	}
	bare := issuedUnlinkCounterInput(t, snapshot, at)
	issued, err := identity.NewAccountUnlinkCounterCommand(bare, snapshot.Counters)
	if err != nil {
		t.Fatal(err)
	}

	current, err := NewRepository(protectedConfig(t, newKey, oldKey))
	if err != nil {
		t.Fatal(err)
	}
	retry, retryPlan, err := current.PrepareAccountUnlinkPreparationCountersWithRetainedKeys(spec, bearer, subject, at, snapshot.Counters.KeyVersions)
	if err != nil || retryPlan.Fingerprint != plan.Fingerprint {
		t.Fatal("adding a digest key changed the original counter plan:", err)
	}
	for name, command := range map[string]identity.Command{"original": original, "retry": retry, "issued": issued} {
		t.Run(name, func(t *testing.T) {
			restored, err := current.restoreCounter(command, plan)
			if err != nil {
				t.Fatal("same counter plan cannot be restored:", err)
			}
			binding := restored.command.Bindings()
			if restored.scope.Operation != "identity.account.unlink" || restored.subject != subject ||
				binding.PreparedAt != at || len(binding.Targets) != 4 || len(binding.Targets[0].Keys) != 1 ||
				len(restored.current.Targets[0].Keys) != 2 {
				t.Fatal("restoration changed original authority or lost current key policy")
			}
			if err := restored.validateAt(at.Add(15*time.Minute - time.Microsecond)); err != nil {
				t.Fatal("live original interval rejected:", err)
			}
			if err := restored.validateAt(at.Add(15 * time.Minute)); err == nil {
				t.Fatal("restoration extended original expiry")
			}
		})
	}
	if err := current.ValidateCommandCounters(bare, plan); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("bare unlink accepted a prepared plan:", err)
	}
	foreign := plan
	foreign.Fingerprint[0] ^= 1
	if err := current.ValidateCommandCounters(issued, foreign); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("foreign counter plan accepted:", err)
	}
	dropped, err := NewRepository(protectedConfig(t, newKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := dropped.ValidateCommandCounters(original, plan); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("restored counters after original key removal:", err)
	}
	subject.Session = "different-session"
	if _, _, err := current.PrepareAccountUnlinkPreparationCounters(spec, bearer, subject, at); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("foreign trusted session admitted:", err)
	}
}

func unlinkCounterInput(t *testing.T, at time.Time) (identity.AccountUnlinkPreparationCommand, authentication.BearerCredential, risk.Subject) {
	t.Helper()
	feature, _ := protectedCommand(t, "counter-tenant").Feature()
	b := feature.Binding
	b.OperationID, b.SchemaID, b.RecordID = "identity.account.unlink", "identity-account", "social-account"
	const session = "original-session"
	return identity.AccountUnlinkPreparationCommand{
			Binding: b,
			Change: identity.AccountUnlinkChange{
				TenantID: b.TenantID, UserID: b.UserID, AccountID: "social-account",
				ExpectedUserVersion: 1, ExpectedAccountVersion: 1,
				ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1,
			},
			SessionID: session, SessionVersion: 1,
			FactorAuthorityVersion: 1,
			Primary: authentication.ReauthenticationProof{
				Proof: authentication.Proof{
					ID: "original-password-proof", Tenant: string(b.TenantID), Subject: string(b.UserID),
					Method: "password", Assurance: authentication.AssuranceSingleFactor,
					Purpose: "identity.password.verify", Audience: "identity-backend",
					IssuedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Minute),
				},
				SessionID: session, SessionVersion: 1, Action: b.OperationID,
			},
		}, authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))),
		risk.Subject{User: string(b.UserID), Session: session, Network: "2001:db8::12"}
}

func issuedUnlinkCounterInput(t *testing.T, spec identity.AccountUnlinkPreparationCommand, at time.Time) identity.Command {
	t.Helper()
	const issuer, keyID = "https://identity.example.test", "test-unlink"
	key := bytes.Repeat([]byte{0x41}, 32)
	signer, err := capability.NewHMACSHA256Signer(keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: issuer, ID: keyID, Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := at.Truncate(time.Second)
	payload := capability.Payload{
		Version: 1, Issuer: issuer, Audiences: []string{"identity-backend"}, ID: "test-unlink-child",
		Tenant: string(spec.Binding.TenantID), Subject: string(spec.Binding.UserID),
		Operation: spec.Binding.OperationID, Resource: string(spec.Change.AccountID), MaxUses: 1,
		IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
		Caveats: map[string]string{
			"command_id": string(spec.Binding.CommandID), "session_id": spec.SessionID,
			"session_version": "1", "user_version": "1", "account_version": "1",
			"social_link_version": "1", "credential_version": "1", "policy_version": "1", "revoke_provider": "false",
		},
	}
	token, err := capability.Issue(t.Context(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := capability.Verify(t.Context(), token, keys, capability.VerifyOptions{Issuer: issuer, Now: at, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewAccountUnlinkCommand(identity.AccountUnlinkCommand{
		Binding: spec.Binding, Change: spec.Change, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion, Proof: grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}
