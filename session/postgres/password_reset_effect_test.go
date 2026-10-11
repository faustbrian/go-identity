package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPasswordResetEffectRequiresNativeWork(t *testing.T) {
	for _, c := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "sessions", MaximumDuration: 2 * time.Minute}} {
		if e, err := NewPasswordResetEffect(c); e != nil || err == nil {
			t.Fatal("invalid reset session owner accepted")
		}
	}
	effect, err := NewPasswordResetEffect(Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*PasswordResetEffect{nil, {}, effect} {
		if _, err := e.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned reset transaction accepted")
		}
		if _, err := e.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned reset recovery accepted")
		}
	}
	if _, err := effect.Apply(nil, kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("nil context accepted")
	}
	if fmt.Sprintf("%#v", effect) != "postgres.PasswordResetEffect(redacted)" {
		t.Fatal("reset deployment configuration disclosed")
	}
	if _, err := json.Marshal(effect); err == nil {
		t.Fatal("implicit configuration export accepted")
	}
	if _, err := effect.MarshalText(); err == nil {
		t.Fatal("implicit text export accepted")
	}
}

func TestPasswordResetEffectDigestRetainsEmptyAndCompleteSet(t *testing.T) {
	initial := resetSessionChain()
	if initial == ([32]byte{}) {
		t.Fatal("empty set has no retained evidence")
	}
	one := resetSessionNext(initial, "one", 7)
	two := resetSessionNext(one, "two", 11)
	if initial == one || one == two || two == resetSessionNext(resetSessionNext(initial, "two", 11), "one", 7) || one == resetSessionNext(initial, "one", 8) {
		t.Fatal("selected session identities, versions or order lost")
	}
	life := kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 7, AfterVersion: 8}
	op := passwordResetSessionOperation()
	b := identity.CommandBinding{OperationID: op.OperationID}
	if !resetSessionScope(b, op, life) {
		t.Fatal("closed reset lifecycle denied")
	}
	life.EventType = "password.changed.v1"
	if resetSessionScope(b, op, life) {
		t.Fatal("authenticated change substituted for reset")
	}
}
