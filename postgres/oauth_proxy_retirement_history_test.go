package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func proxyRetirementHistoryFixture(t *testing.T, preview bool) (OAuthProxyOriginRetirementScope, identity.CommandBinding, CommandPlan, [32]byte, []byte, []byte) {
	t.Helper()
	binding, _, final := proxyStartPlanFixture(t)
	purpose := "identity.oauth.proxy-forward"
	if preview {
		binding, _, final = oauthRPPreparationFixture(t, true)
		binding.AnonymousFlowID, binding.RecordID = "AgICAgICAgICAgICAgICAg", "AgICAgICAgICAgICAgICAg"
		binding.CorrelationID = string(binding.CommandID)
		final.Audits[0].EventType, final.Audits[0].RetentionClass = "identity.oauth.start_authorization", "standard"
		purpose = "identity.oauth.callback"
	}
	// Retirement must recover the retained grant even after its original
	// validity ended; decoding must never replace or renew its deadline.
	final.CapabilityIssuance.Grants[0].ExpiresAt = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	fingerprint := [32]byte{71}
	wire, err := encodeFeaturePlan(binding, fingerprint, final)
	if err != nil {
		t.Fatal("encode the genuine final native issuance history", err)
	}
	safe := commandSafeFields(binding, &final.Feature.Operation)
	scope := OAuthProxyOriginRetirementScope{
		TenantID: binding.TenantID, OriginCommandID: binding.CommandID,
		FlowID: identity.PreAuthTransactionID(binding.AnonymousFlowID), GrantPurpose: purpose,
		SourceCommandID: "AwMDAwMDAwMDAwMDAwMDAw", SourceVersion: 7,
	}
	return scope, binding, final, fingerprint, safe, wire
}

func TestOAuthProxyRetirementHistoryPreservesOriginalExpiredGrant(t *testing.T) {
	for _, preview := range []bool{false, true} {
		name := "production"
		if preview {
			name = "preview"
		}
		t.Run(name, func(t *testing.T) {
			scope, _, final, fingerprint, safe, wire := proxyRetirementHistoryFixture(t, preview)
			want := final.CapabilityIssuance.Grants[0]
			beforeSafe, beforeWire := bytes.Clone(safe), bytes.Clone(wire)
			got, err := decodeOAuthProxyRetirementGrant(scope, safe, fingerprint[:], wire)
			if err != nil || got != want || got.ExpiresAt != time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC) {
				t.Fatal("exact retained issuance lost its original purpose, replay identity, proof or expired deadline", err)
			}
			if !bytes.Equal(safe, beforeSafe) || !bytes.Equal(wire, beforeWire) {
				t.Fatal("retirement history decoding mutated the original persisted evidence")
			}
		})
	}
}

func TestOAuthProxyRetirementHistoryRejectsForeignOrIncompleteEvidence(t *testing.T) {
	for _, preview := range []bool{false, true} {
		for _, mode := range []string{
			"foreign-tenant", "foreign-origin", "foreign-flow", "foreign-purpose", "missing-grant", "wrong-grant-purpose",
			"missing-safe-fields", "trailing-safe-field", "changed-safe-binding", "missing-fingerprint", "short-fingerprint",
			"zero-fingerprint", "changed-fingerprint", "missing-wire", "truncated-wire", "trailing-wire", "changed-wire",
		} {
			name := "production/"
			if preview {
				name = "preview/"
			}
			t.Run(name+mode, func(t *testing.T) {
				scope, binding, final, fingerprint, safe, wire := proxyRetirementHistoryFixture(t, preview)
				fp := bytes.Clone(fingerprint[:])
				switch mode {
				case "foreign-tenant":
					scope.TenantID = "foreign-tenant"
				case "foreign-origin":
					scope.OriginCommandID = "BAQEBAQEBAQEBAQEBAQEBA"
				case "foreign-flow":
					scope.FlowID = "BQUFBQUFBQUFBQUFBQUFBQ"
				case "foreign-purpose":
					scope.GrantPurpose = "identity.identifier.verify"
				case "missing-grant":
					final.CapabilityIssuance = nil
					final.Contributors = final.Contributors[:len(final.Contributors)-1]
					var err error
					wire, err = encodeFeaturePlan(binding, fingerprint, final)
					if err != nil {
						t.Fatal("encode the genuine unfinished issuance declaration", err)
					}
				case "wrong-grant-purpose":
					originalPurpose := cborText(string(final.CapabilityIssuance.Grants[0].Purpose))
					if bytes.Count(wire, originalPurpose) != 1 {
						t.Fatal("negative fixture did not isolate the original grant purpose")
					}
					wire = bytes.Replace(wire, originalPurpose, cborText("identity.identifier.verify"), 1)
				case "missing-safe-fields":
					safe = nil
				case "trailing-safe-field":
					safe = append(bytes.Clone(safe), 0)
				case "changed-safe-binding":
					binding.ActorID = "another-service"
					safe = commandSafeFields(binding, &final.Feature.Operation)
				case "missing-fingerprint":
					fp = nil
				case "short-fingerprint":
					fp = fp[:31]
				case "zero-fingerprint":
					clear(fp)
				case "changed-fingerprint":
					fp[0] ^= 1
				case "missing-wire":
					wire = nil
				case "truncated-wire":
					wire = wire[:len(wire)-1]
				case "trailing-wire":
					wire = append(bytes.Clone(wire), 0)
				case "changed-wire":
					wire = bytes.Clone(wire)
					wire[len(wire)/2] ^= 1
				}
				if got, err := decodeOAuthProxyRetirementGrant(scope, safe, fp, wire); err == nil || got != (CapabilityPlan{}) {
					t.Fatal("foreign, incomplete or altered retained history disclosed an original grant")
				}
			})
		}
	}
}

func TestOAuthProxyRetirementHistoryDistinguishesPreviewFromOrdinaryRP(t *testing.T) {
	scope, binding, final, fingerprint, _, _ := proxyRetirementHistoryFixture(t, true)
	// Ordinary RP initiation names its own command as the transaction record;
	// preview binding names the independently issued browser flow instead.
	binding.RecordID = string(binding.CommandID)
	wire, err := encodeFeaturePlan(binding, fingerprint, final)
	if err != nil {
		t.Fatal("encode the genuine ordinary RP initiation profile", err)
	}
	safe := commandSafeFields(binding, &final.Feature.Operation)
	if got, err := decodeOAuthProxyRetirementGrant(scope, safe, fingerprint[:], wire); err == nil || got != (CapabilityPlan{}) {
		t.Fatal("ordinary RP history acquired preview browser-grant retirement authority")
	}

	binding, _, final = oneTapStartPreparationFixture(t)
	binding.CorrelationID = string(binding.CommandID)
	final.Audits[0].RetentionClass = "protected"
	wire, err = encodeFeaturePlan(binding, fingerprint, final)
	if err != nil {
		t.Fatal("encode the genuine different native issuance operation", err)
	}
	scope.OriginCommandID, scope.FlowID = binding.CommandID, identity.PreAuthTransactionID(binding.AnonymousFlowID)
	scope.GrantPurpose = string(final.CapabilityIssuance.Grants[0].Purpose)
	safe = commandSafeFields(binding, &final.Feature.Operation)
	if got, err := decodeOAuthProxyRetirementGrant(scope, safe, fingerprint[:], wire); err == nil || got != (CapabilityPlan{}) {
		t.Fatal("another native initiation operation acquired proxy-custody retirement authority")
	}
}
