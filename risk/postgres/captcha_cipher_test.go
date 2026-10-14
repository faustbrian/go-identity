package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestCaptchaOriginalResponseEncryptionConservesExactCustody(t *testing.T) {
	issue, _ := captchaIssueFixture(t, captchaFlowFixture())
	command, err := MapCaptchaIssue(issue, captchaCommandBinding(issue.Prepared()))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := command.Feature()
	record, err := issue.Materialize(issue.Prepared().PreparedAt.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := newRecordCipher(map[string][]byte{"wrap-v1": bytes.Repeat([]byte{0x71}, 32)}, "wrap-v1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cipher.sealCaptcha(context.Background(), s.Binding, record)
	if err != nil || bytes.Contains(encoded, []byte(record.Reference.Reveal())) {
		t.Fatal("plaintext or failed custody seal", err)
	}
	metadata := record
	metadata.Reference = risk.CaptchaEvidenceRef{}
	recovered, err := cipher.openCaptcha(context.Background(), s.Binding, metadata, encoded)
	if err != nil || recovered != record {
		t.Fatal("original response changed", err)
	}
	for _, change := range []func(*risk.CaptchaEvidenceRecord){
		func(r *risk.CaptchaEvidenceRecord) { r.ExpiresAt = r.ExpiresAt.Add(time.Microsecond) },
		func(r *risk.CaptchaEvidenceRecord) { r.IssuedAt = r.IssuedAt.Add(time.Microsecond) },
		func(r *risk.CaptchaEvidenceRecord) { r.IntentDigest[0] ^= 1 },
		func(r *risk.CaptchaEvidenceRecord) { r.ProofDigest[0] ^= 1 },
		func(r *risk.CaptchaEvidenceRecord) { r.EvidenceDigest[0] ^= 1 },
		func(r *risk.CaptchaEvidenceRecord) { r.Hostname = "other.example.com" },
		func(r *risk.CaptchaEvidenceRecord) { r.KeyVersion++ },
	} {
		wrong := metadata
		change(&wrong)
		if got, err := cipher.openCaptcha(context.Background(), s.Binding, wrong, encoded); err == nil || got != (risk.CaptchaEvidenceRecord{}) {
			t.Fatal("altered metadata decrypted")
		}
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.ActorID = "other" },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "other" },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = ""; b.UserID = "anonymous-flow" },
	} {
		wrong := s.Binding
		change(&wrong)
		if got, err := cipher.openCaptcha(context.Background(), wrong, metadata, encoded); err == nil || got != (risk.CaptchaEvidenceRecord{}) {
			t.Fatal("foreign scope decrypted")
		}
	}
}
