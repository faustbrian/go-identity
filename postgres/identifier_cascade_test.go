package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func removalCascadeConfig() IdentifierRemovalCascadeConfig {
	c := IdentifierRemovalCascadeConfig{PolicyVersion: 101, Reasons: []string{"user-requested"}, MaximumDuration: time.Hour, ConsumerContracts: map[string]StatusConsumerContract{}}
	for _, id := range identity.IdentifierRemovalConsumers() {
		c.ConsumerContracts[id] = StatusConsumerContract{Version: 1, Fingerprint: [32]byte{7}}
	}
	return c
}

func TestIdentifierRemovalCascadeFreezesCompletePendingManifest(t *testing.T) {
	c := removalCascadeConfig()
	p, err := freezeIdentifierRemovalCascade(c)
	if err != nil {
		t.Fatal(err)
	}
	c.ConsumerContracts["audit"] = StatusConsumerContract{}
	c.Reasons[0] = "changed"
	if p.config.ConsumerContracts["audit"].Version != 1 || p.config.Reasons[0] != "user-requested" || len(p.definition) == 0 {
		t.Fatal("caller mutation changed retained admission policy")
	}
	for _, alter := range []func(*IdentifierRemovalCascadeConfig){
		func(c *IdentifierRemovalCascadeConfig) { delete(c.ConsumerContracts, "sso") },
		func(c *IdentifierRemovalCascadeConfig) {
			c.ConsumerContracts["invented"] = StatusConsumerContract{Version: 1, Fingerprint: [32]byte{1}}
		},
		func(c *IdentifierRemovalCascadeConfig) {
			c.ConsumerContracts["audit"] = StatusConsumerContract{Version: 1}
		},
		func(c *IdentifierRemovalCascadeConfig) { c.PolicyVersion = 0 },
		func(c *IdentifierRemovalCascadeConfig) { c.MaximumDuration = 0 },
		func(c *IdentifierRemovalCascadeConfig) { c.Reasons = []string{"user-requested", "user-requested"} },
		func(c *IdentifierRemovalCascadeConfig) { c.Reasons = []string{"mailbox@example.test"} },
	} {
		bad := removalCascadeConfig()
		alter(&bad)
		if _, err := freezeIdentifierRemovalCascade(bad); err == nil {
			t.Fatal("incomplete/unversioned consumer policy admitted")
		}
	}
}

func TestIdentifierRemovalCascadeMigrationRetainsStatusHistory(t *testing.T) {
	base := StatusMigrationSource{Base: MigrationSource{}, Version: 10}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	history, err := (IdentifierRemovalCascadeMigrationSource{Base: base, Version: 11}).Load(context.Background())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal("missing forward cascade support", err)
	}
	for n := range original {
		if history[n].UpSQL() != original[n].UpSQL() || history[n].Version() != original[n].Version() {
			t.Fatal("existing populated status history rewritten")
		}
	}
	if history[len(history)-1].DownSQL() != "" {
		t.Fatal("destructive cascade history rollback offered")
	}
	if _, err := (IdentifierRemovalCascadeMigrationSource{Base: MigrationSource{}, Version: 11}).Load(context.Background()); err == nil {
		t.Fatal("cascade schema accepted absent owning status admission tables")
	}
}
