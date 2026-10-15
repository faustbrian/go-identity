package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestReauthenticationSigningCustodyCopiesAndRedacts(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	public := bytes.Clone(private.Public().(ed25519.PublicKey))
	key, err := NewReauthenticationSigningKey("evidence-1", private)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	r := originalReauthenticationFixture(t)
	r.Signature = nil
	r, err = key.sign(r)
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := r.SigningBytes()
	if !ed25519.Verify(public, frame, r.Signature) {
		t.Fatal("caller buffer mutation changed retained signing custody")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, key), "evidence-1") {
			t.Fatal("key diagnostics revealed configuration")
		}
	}
	if _, err := json.Marshal(key); err == nil {
		t.Fatal("signing key serialized")
	}
	if _, err := NewReauthenticationSigningKey("evidence-1", make([]byte, 64)); err == nil {
		t.Fatal("inconsistent Ed25519 key accepted")
	}
	if _, err := NewReauthenticationSigningKey("", ed25519.NewKeyFromSeed(make([]byte, 32))); err == nil {
		t.Fatal("empty key identity accepted")
	}
}

func TestReauthenticationServiceZeroNeverDeliversProof(t *testing.T) {
	for _, service := range []*ReauthenticationService{nil, {}} {
		result, err := service.Verify(context.Background(), ReauthenticationRequest{})
		if err == nil || result.Proof != (auth.ReauthenticationProof{}) {
			t.Fatal("unconfigured service delivered authority")
		}
		result, err = service.Recover(context.Background(), "tenant", "aaaaaaaaaaaaaaaaaaaaaa", authorization.DecisionContext{})
		if err == nil || result.Proof != (auth.ReauthenticationProof{}) {
			t.Fatal("unconfigured recovery delivered authority")
		}
	}
}

func TestReauthenticationPhaseRequiresPrivateLiveCustody(t *testing.T) {
	for _, phase := range []*reauthenticationPhase{nil, {}, {service: &ReauthenticationService{}}} {
		if err := phase.ValidateFeatureCommand(identity.Command{}, kernel.CommandPlan{}); err == nil {
			t.Fatal("public structural command bypassed live comparison custody")
		}
		if _, err := phase.ApplyFeature(context.Background(), kernel.Work{}, identity.Command{}); err == nil {
			t.Fatal("unowned Work admitted proof issuance")
		}
		status, err := phase.RecoverParticipant(context.Background(), kernel.RecoveryWork{})
		if err == nil || status != kernel.RecoveryUnknown {
			t.Fatal("unowned recovery claimed commitment")
		}
	}
}
