package apikey_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
)

func FuzzOrganizationPositiveProjectionBlob(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(`{"Schema":1,"Organization":{"OwnerKind":2}}`))
	f.Fuzz(func(t *testing.T, blob []byte) {
		if len(blob) > 65537 {
			t.Skip()
		}
		_, base, request, config := positiveProjectionFixture(t)
		source := &organizationProjectionSource{projectionContractSource: base, organizationVersion: 3}
		config.Verifier, config.Authority = source, nil
		codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source)
		if err != nil {
			t.Fatal(err)
		}
		admission, original, err := codec.Begin(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := codec.Complete(context.Background(), admission, blob)
		if err != nil || out.Result == nil || out.Validate() != nil || out.AttemptID != original.AttemptID || out.Fingerprint != original.Fingerprint || out.Original != original.Original || out.Quota == nil || *out.Quota != *original.Quota || out.Result.ValidUntil.After(original.Result.ValidUntil) || base.verifications != 1 {
			t.Fatal("hostile organization projection changed real source custody or authority", err)
		}
	})
}
