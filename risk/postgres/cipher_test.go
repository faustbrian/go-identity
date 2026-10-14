package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestOriginalResponseEncryptionBindsMetadataAndRetainsOriginalTimes(t *testing.T) {
	issue, _ := evaluatedIssue(t, risk.PhoneResetInitiation)
	r, err := issue.Materialize(issue.Prepared().PreparedAt.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	c, err := MapIssue(issue, issueBinding(issue.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.Feature()
	cipher, err := newRecordCipher(map[string][]byte{"wrap-v1": bytes.Repeat([]byte{0x71}, 32)}, "wrap-v1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cipher.seal(context.Background(), s.Binding, r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(r.Reference.Reveal())) || len(encoded) > 1024 {
		t.Fatal("plaintext or unbounded journal")
	}
	metadata := r
	metadata.Reference = risk.RiskEvidenceRef{}
	recovered, err := cipher.open(context.Background(), s.Binding, metadata, encoded)
	if err != nil || recovered != r {
		t.Fatal("original response changed", err)
	}
	changed := metadata
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Microsecond)
	if _, err := cipher.open(context.Background(), s.Binding, changed, encoded); err == nil {
		t.Fatal("freshness reset authenticated")
	}
	b := s.Binding
	b.TenantID = "other"
	if _, err := cipher.open(context.Background(), b, metadata, encoded); err == nil {
		t.Fatal("cross-tenant ciphertext authenticated")
	}
	for _, change := range []func(*risk.EvidenceRecord){
		func(r *risk.EvidenceRecord) { r.IntentDigest[0] ^= 1 },
		func(r *risk.EvidenceRecord) { r.ProofDigest[0] ^= 1 },
		func(r *risk.EvidenceRecord) { r.EvidenceDigest[0] ^= 1 },
		func(r *risk.EvidenceRecord) { r.KeyVersion++ },
		func(r *risk.EvidenceRecord) { r.IssuedAt = r.IssuedAt.Add(time.Microsecond) },
	} {
		changed := metadata
		change(&changed)
		if _, err := cipher.open(context.Background(), s.Binding, changed, encoded); err == nil {
			t.Fatal("changed record metadata authenticated")
		}
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.UserID = "other" },
		func(b *identity.CommandBinding) { b.ActorID = "other" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
		func(b *identity.CommandBinding) { b.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(b *identity.CommandBinding) { b.RecordID = "other" },
		func(b *identity.CommandBinding) { b.PolicyID = "other" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.CorrelationID = "other" },
	} {
		changed := s.Binding
		change(&changed)
		if _, err := cipher.open(context.Background(), changed, metadata, encoded); err == nil {
			t.Fatal("changed exact command scope authenticated")
		}
	}
	// Separate phone-reset purposes have independently signed intent identities.
	other, _ := evaluatedIssue(t, risk.PhoneResetCompletion)
	oc, err := MapIssue(other, issueBinding(other.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	os, _ := oc.Feature()
	otherMetadata, err := other.Materialize(r.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	otherMetadata.Reference = risk.RiskEvidenceRef{}
	if _, err := cipher.open(context.Background(), os.Binding, otherMetadata, encoded); err == nil {
		t.Fatal("other purpose decrypted original response")
	}
	if _, err := risk.NewEvidenceExecution(other.Intent(), risk.EvidenceCommitted, r); err == nil {
		t.Fatal("other purpose admitted original bearer")
	}
	corrupt := bytes.Clone(encoded)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := cipher.open(context.Background(), s.Binding, metadata, corrupt); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	rotated, err := newRecordCipher(map[string][]byte{"wrap-v1": bytes.Repeat([]byte{0x71}, 32), "wrap-v2": bytes.Repeat([]byte{0x72}, 32)}, "wrap-v2")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.open(context.Background(), s.Binding, metadata, encoded); err != nil || got != r {
		t.Fatal("rotation lost original reference", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cipher.open(ctx, s.Binding, metadata, encoded); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, err := cipher.open(context.Background(), s.Binding, metadata, make([]byte, 1025)); err == nil {
		t.Fatal("oversized envelope accepted")
	}
}
