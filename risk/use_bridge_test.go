package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEvidenceUseNativeBridgePreservesScopeWithoutAuthority(t *testing.T) {
	now := testContext().Now
	var record EvidenceRecord
	executor := evidenceExecutor{resolve: missingEvidence, execute: func(_ context.Context, issue EvidenceIssue) (EvidenceExecution, error) {
		var err error
		record, err = issue.Materialize(now)
		if err != nil {
			t.Fatal(err)
		}
		return NewEvidenceExecution(issue.Intent(), EvidenceCommitted, record)
	}}
	config := issuerConfig(t, &now, executor)
	issuer, err := NewPhoneEvidenceIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	original := issuanceRequest()
	if _, err := issuer.Evaluate(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	request := EvidenceUseRequest{CommandID: "AgICAgICAgICAgICAgICAg", Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}
	use, err := issuer.PrecheckUse(context.Background(), original, request, record)
	if err != nil {
		t.Fatal(err)
	}
	p := use.Prepared()
	claim, err := config.Keys[0].RestoreUse(p)
	if err != nil || claim.Prepared() != p || claim.Validate(now) != nil {
		t.Fatal("native bridge failed", err)
	}
	if p.Binding.CommandID != original.CommandID || p.ConsumerCommandID != request.CommandID || p.ConsumerActor != request.Actor || p.EvidenceDigest != record.EvidenceDigest || p.ProofDigest != record.ProofDigest || !p.IssuedAt.Equal(record.IssuedAt) || !p.ExpiresAt.Equal(record.ExpiresAt) || !p.CheckedAt.Equal(now) {
		t.Fatal("bridge changed original scope")
	}
	for _, mutate := range []func(*PreparedEvidenceUse){
		func(p *PreparedEvidenceUse) { p.Binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(p *PreparedEvidenceUse) { p.Binding.Tenant += "x" },
		func(p *PreparedEvidenceUse) { p.Binding.Subject += "x" },
		func(p *PreparedEvidenceUse) { p.Binding.Actor += "x" },
		func(p *PreparedEvidenceUse) { p.Binding.RecoveryOperation = "identity.phone.password-reset-complete" },
		func(p *PreparedEvidenceUse) { p.Binding.Purpose = "phone-password-reset-complete" },
		func(p *PreparedEvidenceUse) { p.Binding.Phase = PhoneResetCompletion },
		func(p *PreparedEvidenceUse) { p.Binding.PolicyVersion++ },
		func(p *PreparedEvidenceUse) { p.Binding.KeyVersion++ },
		func(p *PreparedEvidenceUse) { p.Binding.IntentDigest[0] ^= 1 },
		func(p *PreparedEvidenceUse) { p.ConsumerCommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(p *PreparedEvidenceUse) { p.ConsumerActor += "x" },
		func(p *PreparedEvidenceUse) { p.EvidenceDigest[0] ^= 1 },
		func(p *PreparedEvidenceUse) { p.ProofDigest[0] ^= 1 },
		func(p *PreparedEvidenceUse) { p.IssuedAt = p.IssuedAt.Add(-time.Microsecond) },
		func(p *PreparedEvidenceUse) { p.CheckedAt = p.CheckedAt.Add(time.Nanosecond) },
		func(p *PreparedEvidenceUse) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
		func(p *PreparedEvidenceUse) { p.Signature[0] ^= 1 },
	} {
		changed := p
		mutate(&changed)
		bad, err := config.Keys[0].RestoreUse(changed)
		if err == nil || bad.Prepared() != (PreparedEvidenceUse{}) {
			t.Fatal("signed scalar changed")
		}
	}
	if use.Prepared() != p {
		t.Fatal("projection aliased original")
	}
	for _, mutate := range []func(*PreparedEvidenceUse){
		func(p *PreparedEvidenceUse) { p.ConsumerCommandID = p.Binding.CommandID },
		func(p *PreparedEvidenceUse) { p.ConsumerCommandID = strings.Repeat("a", 4096) },
		func(p *PreparedEvidenceUse) { p.ConsumerActor = strings.Repeat("a", 4096) },
		func(p *PreparedEvidenceUse) { p.EvidenceDigest = [32]byte{} },
		func(p *PreparedEvidenceUse) { p.ProofDigest = [32]byte{} },
		func(p *PreparedEvidenceUse) { p.CheckedAt = p.IssuedAt.Add(-time.Nanosecond) },
		func(p *PreparedEvidenceUse) { p.CheckedAt = p.ExpiresAt },
		func(p *PreparedEvidenceUse) { p.CheckedAt = p.CheckedAt.In(time.FixedZone("same-instant", 3600)) },
		func(p *PreparedEvidenceUse) { p.ExpiresAt = p.IssuedAt.Add(2*time.Minute + time.Microsecond) },
		func(p *PreparedEvidenceUse) { p.IssuedAt = p.IssuedAt.Add(time.Nanosecond) },
	} {
		changed := p
		mutate(&changed)
		// Even a signed out-of-profile declaration must not restore.
		changed.Signature = useEvidenceSignature(config.Keys[0], changed)
		bad, err := config.Keys[0].RestoreUse(changed)
		if err == nil || bad.Prepared() != (PreparedEvidenceUse{}) {
			t.Fatal("signed invalid declaration")
		}
	}
	for _, mutate := range []func(*EvidenceKey){func(k *EvidenceKey) { k.signing[0] ^= 1 }, func(k *EvidenceKey) { k.digest[0] ^= 1 }, func(k *EvidenceKey) { k.version++ }} {
		key := config.Keys[0]
		mutate(&key)
		if _, err := key.RestoreUse(p); err == nil {
			t.Fatal("wrong key pair restored")
		}
	}
	unsigned := p
	unsigned.Signature = [32]byte{}
	if _, err := config.Keys[0].RestoreUse(unsigned); err == nil {
		t.Fatal("unsigned projection")
	}
	foreignDomain := p
	foreignDomain.Signature = evidenceMAC(config.Keys[0].signing, "identity-risk-evidence-prepared-v1", nil)
	if _, err := config.Keys[0].RestoreUse(foreignDomain); err == nil {
		t.Fatal("foreign signature domain")
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{p, claim} {
		if _, err := value.MarshalJSON(); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("native metadata serialized")
		}
		if _, err := value.MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("native metadata serialized")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), record.Reference.Reveal()) || strings.Contains(fmt.Sprintf("%+v", value), original.CommandID) {
			t.Fatal("native formatting leaked")
		}
	}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), record.ExpiresAt, record.ExpiresAt.Add(time.Microsecond)} {
		if claim.Validate(at) == nil {
			t.Fatal("claim expanded freshness")
		}
	}
	if claim.Validate(record.ExpiresAt.Add(-time.Microsecond)) != nil {
		t.Fatal("claim shortened interval")
	}
	historical, err := config.Keys[0].RestoreUse(p)
	if err != nil || historical.Prepared() != p || historical.Validate(record.ExpiresAt) == nil {
		t.Fatal("restoration renewed expired claim")
	}
	var zero EvidenceUse
	if zero.Prepared() != (PreparedEvidenceUse{}) {
		t.Fatal("zero minted projection")
	}
	var zeroKey EvidenceKey
	if _, err := zeroKey.RestoreUse(p); err == nil {
		t.Fatal("zero key")
	}
}
