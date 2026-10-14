package mfapostgres

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestFactorVerificationSigningRetainsOriginalFrameAndOwnedKey(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	for _, id := range []string{"", "key with spaces", "nonascii-é", "key\n"} {
		if key, err := NewFactorVerificationSigningKey(id, private); err == nil || key.sign != nil {
			t.Fatal("invalid evidence key ID admitted")
		}
	}
	signer, err := NewFactorVerificationSigningKey("factor-original-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	r := factorVerificationFixture(t).Original
	r.Signature = nil
	signed, err := signer.sign(r)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := signed.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(frame)
	if signed.KeyID != "factor-original-v1" || signed.Proof != r.Proof || signed.CredentialID != r.CredentialID || signed.CredentialVersion != r.CredentialVersion || !ed25519.Verify(public, frame, signed.Signature) {
		t.Fatal("signing changed original frame or borrowed caller key")
	}
	id, copy := signer.public()
	clear(copy)
	same, again := signer.public()
	if id != same || !bytes.Equal(again, public) {
		t.Fatal("public-key projection mutated native key custody")
	}
}
