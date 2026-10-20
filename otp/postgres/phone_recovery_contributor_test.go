package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func TestPhoneRecoveryContributorSelectsExactJointCustody(t *testing.T) {
	codec, attempt, input, authority, _ := phoneRecoveryCommandFixture(t)
	mapped, plan, err := codec.MapPhonePasswordResetWithAuthority(t.Context(), attempt, 3, input, authority)
	if err != nil {
		t.Fatal(err)
	}
	config := ContributorConfig{Schema: "otp_store", Codec: codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}}
	owner, err := NewPhoneRecoveryContributor(config)
	if err != nil {
		t.Fatal("exact invocation-local owner unavailable", err)
	}
	if err := owner.ValidateOTPAttemptCommand(mapped, plan); err != nil {
		t.Fatal("exact mapped compound input rejected", err)
	}
	metadata, _ := mapped.PhonePasswordResetInputFeature()
	_, proof, sms, totp, _ := mapped.PhonePasswordResetInputCustody()
	cookie, _ := mapped.PhonePasswordResetPreAuthCookie()
	generated, err := identity.NewFeaturePhonePasswordResetCommand(metadata, "$fixture$replacement", proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	generated, err = identity.BindPhonePasswordResetPreAuth(generated, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.ValidateOTPAttemptCommand(generated, plan); err != nil {
		t.Fatal("exact generated compound custody rejected", err)
	}
	if _, ok := generated.Feature(); ok {
		t.Fatal("generated custody downgraded to generic feature")
	}
	if _, ok := generated.OneTimeCode(); ok {
		t.Fatal("generated custody downgraded to one-code command")
	}
	ordinary, err := NewContributor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := ordinary.ValidateOTPAttemptCommand(mapped, plan); err == nil {
		t.Fatal("unselected ordinary owner acquired compound profile")
	}
	generic, err := identity.NewFeatureOneTimeCodePreAuthCommand(metadata, sms, cookie)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []identity.Command{{}, generic, input} {
		if err := owner.ValidateOTPAttemptCommand(command, plan); err == nil {
			t.Fatal("zero, generic or unmapped input accepted")
		}
	}
	if _, err := NewPhoneRecoveryContributor(ContributorConfig{}); err == nil {
		t.Fatal("unconfigured invocation-local owner accepted")
	}
	if _, err := owner.PreparePhoneRecovery(context.Background(), generated, plan, PhoneRecoveryPreparation{}); err == nil {
		t.Fatal("missing encrypted factor custody accepted")
	}
}

func TestPhoneRecoveryCustodyRejectsDisclosure(t *testing.T) {
	_, _, command, _, _ := phoneRecoveryCommandFixture(t)
	populated := PhoneRecoveryCustody{state: &phoneRecoveryCustody{command: command}}
	preparation := PhoneRecoveryPreparation{ValidUntil: time.Now().Add(time.Minute)}
	for _, value := range []any{PhoneRecoveryPreparation{}, PhoneRecoveryCustody{}, &PhoneRecoveryPreparation{}, &PhoneRecoveryCustody{}, populated, &populated, preparation, &preparation} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			for _, nested := range []any{value, []any{value}, struct{ Value any }{value}} {
				if text := fmt.Sprintf(verb, nested); !strings.Contains(text, "redacted") || strings.Contains(text, "state:") || strings.Contains(text, "ValidUntil:") {
					t.Fatalf("new recovery custody is not redacted for %s", verb)
				}
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, otp.ErrSensitiveSerialization) {
			t.Fatal("new recovery custody allowed JSON disclosure")
		}
		text, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("new recovery custody has no text disclosure boundary")
		}
		if _, err := text.MarshalText(); !errors.Is(err, otp.ErrSensitiveSerialization) {
			t.Fatal("new recovery custody allowed text disclosure")
		}
	}
}
