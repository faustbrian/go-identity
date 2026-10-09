package passwordpostgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	password "github.com/faustbrian/go-identity/password"
	primitive "github.com/faustbrian/go-password"
	"github.com/jackc/pgx/v5/pgtype"
)

func storedFixture(t *testing.T) (password.CredentialKey, credentialRow, primitive.Policy) {
	t.Helper()
	limits := primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2}
	policy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: limits})
	if err != nil {
		t.Fatal("test policy invalid")
	}
	service, err := primitive.New(policy)
	if err != nil {
		t.Fatal("test primitive invalid")
	}
	hash, err := service.Hash(context.Background(), []byte("synthetic-test-password"))
	if err != nil {
		t.Fatal("test material unavailable")
	}
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	return password.CredentialKey{TenantID: "tenant", SubjectID: "user"}, credentialRow{tenant: "tenant", user: "user", status: "active", userVersion: "3", epoch: "5", id: "password", owner: "identity/password", referenceVersion: "7", materialVersion: "7", algorithm: "argon2id", hash: hash.String(), kind: 1, enabled: true, created: now, updated: now}, policy
}

func TestCredentialDecoderRejectsCorruptPrimaryMaterial(t *testing.T) {
	key, base, policy := storedFixture(t)
	for name, edit := range map[string]func(*credentialRow){
		"foreign tenant":     func(r *credentialRow) { r.tenant = "foreign" },
		"foreign user":       func(r *credentialRow) { r.user = "foreign" },
		"missing credential": func(r *credentialRow) { r.id = "" },
		"foreign owner":      func(r *credentialRow) { r.owner = "identity/oauth" },
		"narrowed kind":      func(r *credentialRow) { r.kind = 257 },
		"invalid status":     func(r *credentialRow) { r.status = "restored" },
		"zero epoch":         func(r *credentialRow) { r.epoch = "0" },
		"fractional version": func(r *credentialRow) { r.referenceVersion = "7.0" },
		"material version":   func(r *credentialRow) { r.materialVersion = "8" },
		"overflow":           func(r *credentialRow) { r.userVersion = "18446744073709551616" },
		"leading zero":       func(r *credentialRow) { r.epoch = "05" },
		"algorithm":          func(r *credentialRow) { r.algorithm = "bcrypt" },
		"corrupt hash":       func(r *credentialRow) { r.hash = "malformed" },
		"zero creation":      func(r *credentialRow) { r.created = time.Time{} },
		"time reversal":      func(r *credentialRow) { r.updated = r.created.Add(-time.Second) },
		"time precision":     func(r *credentialRow) { r.updated = r.updated.Add(time.Nanosecond) },
		"infinite expiry":    func(r *credentialRow) { r.expiry = pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity} },
	} {
		t.Run(name, func(t *testing.T) {
			row := base
			edit(&row)
			got, err := decodeCredential(key, row, policy.Limits())
			if !errors.Is(err, password.ErrPasswordWork) || got.EncodedHash().String() != "" {
				t.Fatal("corrupt primary record granted material")
			}
		})
	}
	for _, value := range []uint64{1<<53 + 1, 1 << 63, math.MaxUint64} {
		row := base
		version := strconv.FormatUint(value, 10)
		row.userVersion = version
		row.epoch = version
		row.referenceVersion = version
		row.materialVersion = version
		got, err := decodeCredential(key, row, policy.Limits())
		if err != nil || got.Authority().Credential.Version != value || got.Authority().AuthorityVersion != value || got.Authority().User.Version != value {
			t.Fatal("uint64 authority narrowed")
		}
	}
}

func TestReaderAndMigrationZeroValuesFailClosed(t *testing.T) {
	if got, err := NewRepository(nil, Config{}); got != nil || !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("zero configuration accepted")
	}
	for _, reader := range []*Repository{nil, {}} {
		got, err := reader.ReadPasswordCredential(context.Background(), password.CredentialKey{})
		if got.EncodedHash().String() != "" || !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("zero reader accepted")
		}
	}
	source := MigrationSource{}
	if _, err := source.Load(nil); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost")
	}
	first, err := source.Load(context.Background())
	if err != nil || len(first) != 3 {
		t.Fatal("migration history missing")
	}
	second, err := source.Load(context.Background())
	if err != nil || len(second) != 3 || first[0].Version() != second[0].Version() || first[0].Checksum() != second[0].Checksum() || first[1].Version() != 2 || first[2].Version() != 3 {
		t.Fatal("migration history unstable")
	}
}
