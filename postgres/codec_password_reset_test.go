package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

func passwordResetCodecSpec() identity.FeatureCommandSpec {
	s := featureCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-complete", SchemaID: "password-reset-complete", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func passwordResetCodecProof(t *testing.T, signingByte byte) (capability.Proof, string) {
	t.Helper()
	signer, err := capability.NewHMACSHA256Signer("synthetic-reset", bytes.Repeat([]byte{signingByte}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Already expired: command identity/recovery must not depend on current
	// validity. Actual reservation and native admission remain separate.
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	p := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: "user", Resource: "identity.password/credential", Operation: "identity.password.reset-complete", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "synthetic-reset", Tenant: "tenant", MaxUses: 1}
	wire, err := capability.Issue(context.Background(), p, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return proof, wire
}

func passwordResetCodecCommand(t *testing.T, s identity.FeatureCommandSpec, hash string, proof capability.Proof) identity.Command {
	t.Helper()
	c, err := identity.NewFeaturePasswordResetCommand(s, hash, proof)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPasswordResetCanonicalIntentBindsOriginalCustody(t *testing.T) {
	s, key := passwordResetCodecSpec(), [32]byte{1}
	proof, wire := passwordResetCodecProof(t, 1)
	hash := "$synthetic$private-reset-verifier"
	c := passwordResetCodecCommand(t, s, hash, proof)
	baseline, err := prepareClaim(c, key)
	if err != nil {
		t.Fatal("reset original intent denied", err)
	}
	if baseline.source == nil || baseline.feature == nil || *baseline.feature != s.Operation || baseline.purpose != s.Binding.OperationID || !bytes.Equal(baseline.safeFields, commandSafeFields(s.Binding, &s.Operation)) {
		t.Fatal("original command/safe scope lost")
	}
	for path, value := range map[string]string{"password-reset-hash": hash, "password-reset-proof": wire} {
		mac := hmac.New(sha256.New, key[:])
		mac.Write([]byte("identity-command-secret-v1"))
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(path))))
		mac.Write([]byte(path))
		mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(value))))
		mac.Write([]byte(value))
		if !bytes.Contains(baseline.canonical, mac.Sum(nil)) || bytes.Contains(baseline.safeFields, mac.Sum(nil)) || bytes.Contains(baseline.canonical, []byte(value)) || bytes.Contains(baseline.safeFields, []byte(value)) {
			t.Fatal("custody framing or privacy violated")
		}
	}
	same, err := prepareClaim(c, key)
	if err != nil || !bytes.Equal(same.canonical, baseline.canonical) {
		t.Fatal("original intent unstable")
	}
	changedProof, changedWire := passwordResetCodecProof(t, 2)
	originalParts, changedParts := strings.Split(wire, "."), strings.Split(changedWire, ".")
	if len(originalParts) != len(changedParts) || strings.Join(originalParts[:len(originalParts)-1], ".") != strings.Join(changedParts[:len(changedParts)-1], ".") || originalParts[len(originalParts)-1] == changedParts[len(changedParts)-1] {
		t.Fatal("signature-only control changed payload")
	}
	for name, changed := range map[string]identity.Command{
		"hash":      passwordResetCodecCommand(t, s, hash+"x", proof),
		"signature": passwordResetCodecCommand(t, s, hash, changedProof),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := prepareClaim(changed, key)
			if err != nil || bytes.Equal(got.canonical, baseline.canonical) || !bytes.Equal(got.safeFields, baseline.safeFields) {
				t.Fatal("changed custody collapsed into original intent")
			}
		})
	}
	rotated, err := prepareClaim(c, [32]byte{2})
	if err != nil || rotated.source == nil || bytes.Equal(rotated.canonical, baseline.canonical) {
		t.Fatal("rotation lost original custody")
	}
	retained, err := prepareClaim(*rotated.source, key)
	if err != nil || !bytes.Equal(retained.canonical, baseline.canonical) {
		t.Fatal("retained-key replay changed intent")
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if string(raw) != wire {
			t.Fatal("fingerprinting altered custody")
		}
		return nil
	}); err != nil {
		t.Fatal("fingerprinting consumed custody", err)
	}
	if _, err := prepareClaim(c, key); err == nil {
		t.Fatal("terminal custody resurrected")
	}
}

func TestPasswordResetIntentRejectsMissingCustodyAndPreservesExecutionGate(t *testing.T) {
	s := passwordResetCodecSpec()
	if _, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1}); err == nil {
		t.Fatal("generic metadata omitted required proof/hash")
	}
	proof, _ := passwordResetCodecProof(t, 1)
	c := passwordResetCodecCommand(t, s, "synthetic", proof)
	if _, err := prepareClaim(c, [32]byte{}); err == nil {
		t.Fatal("zero journal key admitted")
	}
	// Fingerprinting alone must not enable native execution. The exact typed
	// reset mutation/capability/session profile is required separately.
	if credentialReplacementOperation(s.Operation) {
		t.Fatal("reset borrowed authenticated change transition")
	}
	_, ordinary, plan := featurePlanFixture(t)
	ordinarySpec, _ := ordinary.Feature()
	plan.SubjectType = "credential"
	plan.Audits[0].RetentionClass = "protected"
	if _, err := FeaturePlanDigest(ordinarySpec.Binding, [32]byte{1}, plan); err != nil {
		t.Fatal("ordinary execution control is not valid", err)
	}
	plan.Feature.Operation = s.Operation
	plan.Feature.Contributor.Owner = "identity/password/postgres"
	plan.Contributors[3] = plan.Feature.Contributor
	plan.Lifecycle = &LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 7, AfterVersion: 8}
	if _, err := FeaturePlanDigest(s.Binding, [32]byte{1}, plan); err == nil {
		t.Fatal("reset admitted without its atomic capability profile")
	}
}

func TestPasswordResetIntentConcurrentTerminalCustody(t *testing.T) {
	proof, _ := passwordResetCodecProof(t, 1)
	c := passwordResetCodecCommand(t, passwordResetCodecSpec(), "synthetic", proof)
	baseline, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			for range 16 {
				got, err := prepareClaim(c, [32]byte{1})
				if err == nil && !bytes.Equal(got.canonical, baseline.canonical) {
					t.Error("concurrent original intent changed")
				}
				if err != nil && (len(got.canonical) != 0 || got.source != nil) {
					t.Error("failed binding retained partial claim")
				}
			}
		})
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := prepareClaim(c, [32]byte{1}); err == nil {
		t.Fatal("post-transfer fingerprint admitted")
	}
}
