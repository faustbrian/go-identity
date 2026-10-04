package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func publicStagingFixture(t *testing.T) (*deliverypostgres.Contributor, deliverypostgres.ContributorConfig, identity.CommandBinding, deliverypostgres.IntentInput) {
	t.Helper()
	provider, err := keyring.New(map[string][]byte{"envelope-a": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := secretenvelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	config := deliverypostgres.ContributorConfig{Deployment: "test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {3}}, ActiveEnvelopeKeyID: "envelope-a", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypostgres.ProviderProfile{1: {Provider: "test-provider", PolicyVersion: 1}}}
	c, err := deliverypostgres.NewContributor(config, service)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: identity.UserID(user), ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.user.create", PolicyID: "policy", PolicyVersion: 1, SchemaID: "fields", SchemaVersion: 1, CorrelationID: "correlation"}
	i := deliverypostgres.IntentInput{Purpose: "verification", SubjectID: string(user), TemplateID: "verify", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), Recipient: delivery.Recipient{Channel: delivery.ChannelEmail, Address: "recipient@example.invalid", ScopeDigest: strings.Repeat("a", 64)}, Rendered: delivery.RenderedMessage{Channel: delivery.ChannelEmail, Locale: "en", Subject: "verify", Body: "synthetic-code", ContentType: "text/plain"}}
	return c, config, b, i
}

func TestPublicPreparationFreezesPlanAndRejectsUnavailableWork(t *testing.T) {
	c, config, b, input := publicStagingFixture(t)
	config.RetainedDigestKeys[1] = [32]byte{9}
	config.ProviderProfiles[1] = deliverypostgres.ProviderProfile{Provider: "other", PolicyVersion: 9}
	prepared, err := c.Prepare(context.Background(), b, []deliverypostgres.IntentInput{input})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Contributor != c.Descriptor() {
		t.Fatal("public declaration unavailable", err)
	}
	original := plan.Intents[0]
	plan.Intents[0].Purpose = "changed"
	plan.Intents = nil
	again, err := prepared.Plan()
	if err != nil || again.Intents[0] != original {
		t.Fatal("caller changed frozen plan", err)
	}
	if err := c.Stage(context.Background(), identitypostgres.Work{}, prepared); err == nil {
		t.Fatal("zero Work admitted")
	}
	var zero deliverypostgres.PreparedDelivery
	if _, err := zero.Plan(); err == nil {
		t.Fatal("zero preparation admitted")
	}
	if err := c.Stage(context.Background(), identitypostgres.Work{}, zero); err == nil {
		t.Fatal("zero staging admitted")
	}
	other, _, _, _ := publicStagingFixture(t)
	if err := other.Stage(context.Background(), identitypostgres.Work{}, prepared); err == nil {
		t.Fatal("foreign preparation admitted")
	}
	for _, v := range []any{prepared, &prepared, config, &config, input, &input, c} {
		if text := fmt.Sprintf("%+v", v); strings.Contains(text, input.Recipient.Address) || strings.Contains(text, input.Rendered.Body) {
			t.Fatal("sensitive preparation leaked")
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("sensitive custody implicitly serialized")
		}
	}
}

func TestPublicPreparationPreservesCancellationBoundsAndExpiry(t *testing.T) {
	c, _, b, input := publicStagingFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Prepare(ctx, b, []deliverypostgres.IntentInput{input}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled preparation issued custody")
	}
	if _, err := c.Prepare(nil, b, []deliverypostgres.IntentInput{input}); err == nil {
		t.Fatal("nil context admitted")
	}
	if _, err := c.Prepare(context.Background(), b, nil); err == nil {
		t.Fatal("empty preparation admitted")
	}
	if _, err := c.Prepare(context.Background(), b, make([]deliverypostgres.IntentInput, 17)); err == nil {
		t.Fatal("unbounded effects admitted")
	}
	input.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond)
	if _, err := c.Prepare(context.Background(), b, []deliverypostgres.IntentInput{input}); !errors.Is(err, delivery.ErrExpired) {
		t.Fatal("expired preparation renewed")
	}
}

func TestPublicMigrationSourcePreservesOwnedHistory(t *testing.T) {
	base := identitypostgres.MigrationSource{}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := deliverypostgres.MigrationSource{Base: base, Version: 10}
	after, err := source.Load(context.Background())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("delivery migration unavailable", err)
	}
	for n, m := range before {
		if m.Checksum() != after[n].Checksum() {
			t.Fatal("kernel migration was rewritten")
		}
	}
	if after[len(before)].DownSQL() != "" {
		t.Fatal("destructive rollback exposed")
	}
	worker, err := (deliverypostgres.MigrationSource{Base: base, Version: 10, WorkerVersion: 11}).Load(context.Background())
	if err != nil || len(worker) != len(after)+1 {
		t.Fatal("worker extension unavailable", err)
	}
	for n, m := range after {
		if m.Checksum() != worker[n].Checksum() {
			t.Fatal("installed delivery history rewritten")
		}
	}
	if worker[len(after)].DownSQL() != "" {
		t.Fatal("worker rollback exposed")
	}
	policy, err := (deliverypostgres.MigrationSource{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 12}).Load(context.Background())
	if err != nil || len(policy) != len(worker)+1 || policy[len(worker)].DownSQL() != "" {
		t.Fatal("policy extension unavailable", err)
	}
	for n, m := range worker {
		if m.Checksum() != policy[n].Checksum() {
			t.Fatal("installed worker history rewritten")
		}
	}
	keyed, err := (deliverypostgres.MigrationSource{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13}).Load(context.Background())
	if err != nil || len(keyed) != len(policy)+1 || keyed[len(policy)].DownSQL() != "" {
		t.Fatal("keyed extension unavailable", err)
	}
	for n, m := range policy {
		if m.Checksum() != keyed[n].Checksum() {
			t.Fatal("installed policy history rewritten")
		}
	}
	state, err := (deliverypostgres.MigrationSource{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14}).Load(context.Background())
	if err != nil || len(state) != len(keyed)+1 || state[len(keyed)].DownSQL() != "" {
		t.Fatal("state extension unavailable", err)
	}
	for n, m := range keyed {
		if m.Checksum() != state[n].Checksum() {
			t.Fatal("installed keyed history rewritten")
		}
	}
	for _, invalid := range []deliverypostgres.MigrationSource{
		{Base: base, Version: 10, PolicyVersion: 12},
		{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 11},
		{Base: base, Version: 10, WorkerVersion: 11, KeyedVersion: 13},
		{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 12},
		{Base: base, Version: 10, StateVersion: 14},
		{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 12, StateVersion: 14},
		{Base: base, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 13},
	} {
		if _, err := invalid.Load(context.Background()); err == nil {
			t.Fatal("invalid policy migration order admitted")
		}
	}
	if _, err := (deliverypostgres.MigrationSource{Base: base, Version: 10, WorkerVersion: 10}).Load(context.Background()); err == nil {
		t.Fatal("worker version collision admitted")
	}
	if _, err := (deliverypostgres.MigrationSource{Base: base, Version: 9}).Load(context.Background()); err == nil {
		t.Fatal("migration version collision admitted")
	}
	if _, err := (deliverypostgres.MigrationSource{}).Load(context.Background()); err == nil {
		t.Fatal("zero migration source admitted")
	}
}
