//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type oneTapCallbackGrantClock struct{ now time.Time }

func (c oneTapCallbackGrantClock) Now() time.Time { return c.now }

func TestOneTapCallbackGrantLoadsOnlyExactOriginalSealedGrant(t *testing.T) {
	ctx, pool, config, counter := oneTapStartIntegrationFixture(t)
	owner, err := NewOneTapStartService(pool, config)
	if err != nil {
		t.Fatal("construct native start owner", err)
	}
	start := func(key string) (identity.CommandID, session.ProviderPreAuthTransactionSpec) {
		t.Helper()
		_, request := oneTapStartIntegrationRequest(t, key)
		result, err := owner.Start(ctx, request)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Replayed {
			t.Fatal("commit native start for callback intake", err)
		}
		browser, ok := result.Browser()
		if !ok {
			t.Fatal("native start did not retain its browser flow")
		}
		record, err := sessionpg.ReadProviderPreAuth(ctx, pool.Raw(), config.Session, config.TenantID, browser.FlowID, owner.selected)
		if err != nil {
			t.Fatal("read original provider flow from primary", err)
		}
		original, err := record.ProviderBindings()
		if err != nil {
			t.Fatal("project original provider flow", err)
		}
		return result.CommandID, original
	}
	command, original := start("onetap-callback-original-grant")
	_, other := start("onetap-callback-other-grant")
	charges := counter.calls
	flow, _ := base64.RawURLEncoding.Strict().DecodeString(string(original.Transaction.Binding.ID))
	otherFlow, _ := base64.RawURLEncoding.Strict().DecodeString(string(other.Transaction.Binding.ID))
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT proof_ciphertext FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow).Scan(&ciphertext); err != nil {
		t.Fatal("read sealed fixture custody", err)
	}
	defer clear(ciphertext)

	restarted, err := NewOneTapStartService(pool, config)
	if err != nil {
		t.Fatal("restart callback intake owner", err)
	}
	loaded, err := restarted.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal("load authentic original callback grant", err)
	}
	defer loaded.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	op := kernel.OneTapStartOperation()
	want := identity.CommandBinding{CommandID: command, TenantID: config.TenantID,
		AnonymousFlowID: string(original.Transaction.Binding.ID), RecordID: string(original.Transaction.Binding.ID), CorrelationID: string(command),
		ActorID: config.Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID,
		PolicyID: config.Issuance.PolicyID, PolicyVersion: config.Issuance.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion}
	if loaded.Original != want || loaded.Grant.Purpose != oneTapCallbackPurpose || loaded.Grant.MaxUses != 1 ||
		loaded.Grant.ReplayKeyVersion != config.Capability.CurrentReplayKeyVersion || loaded.Grant.ReplayDigest == ([32]byte{}) ||
		!loaded.Grant.ExpiresAt.Equal(original.Transaction.Binding.ExpiresAt) {
		t.Fatal("intake changed original command or issuance metadata")
	}
	crypto, err := capability.NewService(config.Capability.Crypto)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := crypto.Verify(ctx, loaded.Proof, oneTapCallbackPurpose, config.Capability.Audience)
	if err != nil || verified.EnvelopeDigest() != loaded.Grant.ProofFingerprint || verified.Payload().ID != loaded.Grant.CapabilityID ||
		!verified.Payload().IssuedAt.Equal(original.Transaction.Binding.IssuedAt) || !verified.Payload().ExpiresAt.Equal(original.Transaction.Binding.ExpiresAt) {
		t.Fatal("intake did not preserve the exact signed original proof", err)
	}
	var unchanged bool
	if err := pool.Raw().QueryRow(ctx, `SELECT
	 (SELECT proof_ciphertext=$3 AND erased_at IS NULL FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2)
	 AND (SELECT state='issued' AND uses=0 AND origin_command_id=$5 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$4)
	 AND (SELECT state='issued' FROM onetap_sessions.preauth_transactions WHERE tenant_id=$1 AND flow_id=$6)`,
		string(config.TenantID), flow, ciphertext, loaded.Grant.CapabilityID, string(command), string(original.Transaction.Binding.ID)).Scan(&unchanged); err != nil || !unchanged || counter.calls != charges {
		t.Fatal("read-only intake changed custody, flow, one-use state or external charges", err)
	}
	t.Run("original lifecycle is exclusive despite verifier skew", func(t *testing.T) {
		binding := original.Transaction.Binding
		for _, test := range []struct {
			name string
			now  time.Time
			deny bool
		}{
			{name: "before issuance", now: binding.IssuedAt.Add(-time.Nanosecond), deny: true},
			{name: "just before expiry", now: binding.ExpiresAt.Add(-time.Nanosecond)},
			{name: "exact expiry", now: binding.ExpiresAt, deny: true},
			{name: "after expiry within verifier skew", now: binding.ExpiresAt.Add(time.Second), deny: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				selected := restarted.config()
				selected.Issuance.Clock = oneTapCallbackGrantClock{now: test.now}
				selected.Capability.Crypto.Clock = func() time.Time { return test.now }
				selected.Capability.Crypto.Skew = time.Minute
				verifier, err := capability.NewService(selected.Capability.Crypto)
				if err != nil {
					t.Fatal(err)
				}
				if grant, err := verifier.Verify(ctx, loaded.Proof, oneTapCallbackPurpose, selected.Capability.Audience); err != nil || grant.EnvelopeDigest() != loaded.Grant.ProofFingerprint {
					t.Fatal("fixture verifier skew did not admit authentic original proof", err)
				}
				copied := *restarted
				copied.config = func() OneTapStartConfig { return selected }
				got, err := copied.loadOneTapCallbackGrant(ctx, original)
				defer got.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
				if test.deny {
					var forbidden identity.ForbiddenError
					if !errors.As(err, &forbidden) || got.Original != (identity.CommandBinding{}) || got.Grant != (kernel.CapabilityPlan{}) || got.Proof.ValidateBounds(1, 65536) == nil {
						t.Fatal("verifier skew extended original flow lifecycle", err)
					}
					return
				}
				if err != nil || got.Original != loaded.Original || got.Grant != loaded.Grant || got.Proof.ValidateBounds(1, 65536) != nil {
					t.Fatal("valid original lifecycle changed sealed grant custody", err)
				}
			})
		}
	})

	deny := func(t *testing.T, supplied session.ProviderPreAuthTransactionSpec) {
		t.Helper()
		got, err := restarted.loadOneTapCallbackGrant(ctx, supplied)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got.Original != (identity.CommandBinding{}) || got.Grant != (kernel.CapabilityPlan{}) || got.Proof.ValidateBounds(1, 65536) == nil {
			t.Fatal("substituted or erased original released callback custody", err)
		}
	}
	for name, change := range map[string]func(*session.ProviderPreAuthTransactionSpec){
		"provider": func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderVersion++ },
		"tenant": func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.TenantID = "other-tenant"
		},
		"origin": func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.Origin = "https://other.example"
		},
		"policy": func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.PolicyVersion++ },
		"operation": func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.Action = "identity.oauth.signin-start"
		},
		"expiry": func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.ExpiresAt = s.Transaction.Binding.ExpiresAt.Add(-time.Second)
		},
		"missing custody": func(s *session.ProviderPreAuthTransactionSpec) {
			id, err := identity.NewPreAuthTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			s.Transaction.Binding.ID = id
		},
	} {
		t.Run(name, func(t *testing.T) {
			supplied := original
			change(&supplied)
			deny(t, supplied)
		})
	}
	t.Run("sealed source and signed metadata must agree", func(t *testing.T) {
		aad, err := restarted.callbackAAD(want, original.Transaction.Binding.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		var stored oneTapStoredCallbackGrant
		defer func() { clear(stored.Proof) }()
		if err := restarted.openOneTap(ctx, aad, ciphertext, 65536, &stored); err != nil {
			t.Fatal("open authentic synthetic fixture", err)
		}
		for name, change := range map[string]func(*oneTapStoredCallbackGrant){
			"source command":    func(s *oneTapStoredCallbackGrant) { s.Original.CorrelationID = "another-command" },
			"proof fingerprint": func(s *oneTapStoredCallbackGrant) { s.Grant.ProofFingerprint = [32]byte{1} },
			"signed ID":         func(s *oneTapStoredCallbackGrant) { s.Grant.CapabilityID = "another-grant" },
			"one-use metadata":  func(s *oneTapStoredCallbackGrant) { s.Grant.MaxUses = 2 },
		} {
			t.Run(name, func(t *testing.T) {
				changed := stored
				change(&changed)
				wire, err := restarted.sealOneTap(ctx, aad, changed, 65536)
				if err != nil {
					t.Fatal("seal mismatched synthetic fixture", err)
				}
				defer clear(wire)
				if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=$3 WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow, wire); err != nil {
					t.Fatal("stage mismatched synthetic fixture", err)
				}
				deny(t, original)
			})
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=$3 WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow, ciphertext); err != nil {
			t.Fatal("restore authentic synthetic fixture", err)
		}
	})
	t.Run("moved ciphertext between authentic flows", func(t *testing.T) {
		var wire []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT proof_ciphertext FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), otherFlow).Scan(&wire); err != nil {
			t.Fatal("read other authentic flow custody", err)
		}
		defer clear(wire)
		if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=$3 WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow, wire); err != nil {
			t.Fatal("move synthetic fixture ciphertext", err)
		}
		deny(t, original)
		if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=$3 WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow, ciphertext); err != nil {
			t.Fatal("restore synthetic fixture ciphertext", err)
		}
	})
	t.Run("erased custody", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=NULL,erased_at=issued_at WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow); err != nil {
			t.Fatal("erase synthetic fixture custody", err)
		}
		deny(t, original)
	})
}
