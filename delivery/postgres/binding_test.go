package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

func TestAnonymousBindingReopensOnlyOriginalFlow(t *testing.T) {
	c, b, p := custodyFixture(t)
	b.Command.UserID = ""
	b.Command.AnonymousFlowID = "flow-a"
	b.Command.OperationID = "identity.otp.send"
	b.Intent.SubjectID = b.Command.AnonymousFlowID
	frozen, envelope, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		t.Fatal("anonymous custody unavailable", err)
	}
	ctx, err := custodyContext(frozen, true)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := c.restore(ctx.AdditionalData(), envelope)
	if err != nil || !reflect.DeepEqual(restored, frozen) {
		t.Fatal("original anonymous binding lost on restart", err)
	}
	opened, err := c.open(context.Background(), restored, envelope)
	if err != nil || !reflect.DeepEqual(opened, p) {
		t.Fatal("original anonymous payload lost on restart", err)
	}
	for _, change := range []func(*payloadBinding){
		func(v *payloadBinding) { v.Command.AnonymousFlowID = "flow-other"; v.Intent.SubjectID = "flow-other" },
		func(v *payloadBinding) {
			v.Command.UserID = identity.UserID(v.Command.AnonymousFlowID)
			v.Command.AnonymousFlowID = ""
		},
		func(v *payloadBinding) { v.Command.TenantID = "tenant-other" },
	} {
		other := frozen
		change(&other)
		aad, err := custodyContext(other, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.restore(aad.AdditionalData(), envelope); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("changed flow or namespace authenticated retained ciphertext", err)
		}
	}
	for _, change := range []func(map[string]string){
		func(v map[string]string) { delete(v, "anonymous_flow") },
		func(v map[string]string) { v["user"] = "flow-a" },
		func(v map[string]string) { v["profile"] = "identity-delivery-payload-v1" },
		func(v map[string]string) { v["anonymous_flow"] = "" },
	} {
		values := ctx.Values()
		change(values)
		aad, err := secretenvelope.NewContext(values)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBinding(aad.AdditionalData()); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("malformed anonymous profile accepted", err)
		}
	}
}

func TestPersistedBindingReopensOriginalCustody(t *testing.T) {
	c, b, p := custodyFixture(t)
	b.Command.RecordID = "account-a"
	b.Intent.EffectIndex = 65535
	b.Command.PolicyVersion = ^uint64(0)
	b.Intent.ProviderConfigVersion = ^uint64(0)
	b.NoOpEquivalent = true
	frozen, envelope, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := custodyContext(frozen, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.restore(ctx.AdditionalData(), envelope)
	if err != nil || !reflect.DeepEqual(got, frozen) {
		t.Fatal("original binding did not survive persistence", err)
	}
	opened, err := c.open(context.Background(), got, envelope)
	if err != nil || !reflect.DeepEqual(opened, p) {
		t.Fatal("persisted binding cannot open original custody", err)
	}
	values := ctx.Values()
	values["tenant"] = "tenant-other"
	changed, err := secretenvelope.NewContext(values)
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.restore(changed.AdditionalData(), envelope)
	if !errors.Is(err, delivery.ErrForbidden) || !reflect.DeepEqual(other, payloadBinding{}) {
		t.Fatal("reconstruction granted authority to changed binding")
	}
	delete(c.keys, frozen.DigestKeyVersion)
	if _, err := c.restore(ctx.AdditionalData(), envelope); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("missing retained key did not deny restored scope")
	}
}

func TestPersistedBindingRejectsMalformedOrDifferentProfiles(t *testing.T) {
	c, b, p := custodyFixture(t)
	frozen, _, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := custodyContext(frozen, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]string){
		func(v map[string]string) { delete(v, "record") },
		func(v map[string]string) { v["unexpected"] = "x" },
		func(v map[string]string) { v["profile"] = "identity-delivery-payload-v2" },
		func(v map[string]string) { v["command_policy_version"] = "01" },
		func(v map[string]string) { v["effect_index"] = "65536" },
		func(v map[string]string) { v["template_version"] = "4294967296" },
		func(v map[string]string) { v["provider_version"] = "18446744073709551616" },
		func(v map[string]string) { v["delivery_policy"] = "+1" },
		func(v map[string]string) { v["digest_key_version"] = "0" },
		func(v map[string]string) { v["command_schema_version"] = "-1" },
		func(v map[string]string) { v["link_mode"] = "255" },
		func(v map[string]string) { v["expiry"] = "0" },
		func(v map[string]string) { v["expiry"] = "253402300800000000" },
		func(v map[string]string) {
			v["intent_digest"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		func(v map[string]string) {
			v["intent_digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
		},
		func(v map[string]string) { v["no_op"] = "1" },
		func(v map[string]string) { v["actor_kind"] = "unrecognized" },
		func(v map[string]string) { v["command"] = "invalid" },
	} {
		values := ctx.Values()
		change(values)
		bad, err := secretenvelope.NewContext(values)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeBinding(bad.AdditionalData()); !errors.Is(err, delivery.ErrInvalidInput) || !reflect.DeepEqual(got, payloadBinding{}) {
			t.Fatal("invalid profile accepted or partial binding returned")
		}
	}
	wire := ctx.AdditionalData()
	for i := range len(wire) {
		if _, err := decodeBinding(wire[:i]); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("truncated binding accepted")
		}
	}
	firstEnd := 4 + int(binary.BigEndian.Uint32(wire[:4]))
	firstEnd += 4 + int(binary.BigEndian.Uint32(wire[firstEnd:firstEnd+4]))
	for _, bad := range [][]byte{
		nil, bytes.Repeat([]byte{0}, 16385), {255, 255, 255, 255},
		append(bytes.Clone(wire), 0),
		append(bytes.Clone(wire[:firstEnd]), wire...),
		append(bytes.Clone(wire[firstEnd:]), wire[:firstEnd]...),
	} {
		if _, err := decodeBinding(bad); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("unbounded or noncanonical binding accepted")
		}
	}
}

func FuzzPersistedBinding(f *testing.F) {
	c, b, p := custodyFixture(f)
	frozen, _, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		f.Fatal(err)
	}
	ctx, err := custodyContext(frozen, true)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ctx.AdditionalData())
	b.Command.UserID = ""
	b.Command.AnonymousFlowID = "flow-a"
	b.Command.OperationID = "identity.otp.send"
	b.Intent.SubjectID = "flow-a"
	anonymous, _, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		f.Fatal(err)
	}
	anonymousContext, err := custodyContext(anonymous, true)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(anonymousContext.AdditionalData())
	f.Add([]byte{})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, wire []byte) {
		b, err := decodeBinding(wire)
		if err != nil {
			if !errors.Is(err, delivery.ErrInvalidInput) || !reflect.DeepEqual(b, payloadBinding{}) {
				t.Fatal("nonclosed malformed-input result")
			}
			return
		}
		ctx, err := custodyContext(b, true)
		if err != nil || !bytes.Equal(ctx.AdditionalData(), wire) {
			t.Fatal("accepted noncanonical binding")
		}
	})
}
