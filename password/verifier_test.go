package password

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

type verificationReadFunc func(context.Context, CredentialKey) (CredentialSnapshot, error)

func editVerificationSnapshot(s *CredentialSnapshot, edit func(*credentialSnapshot)) {
	retained := s.custody()
	edit(&retained)
	s.custody = func() credentialSnapshot { return retained }
}

func (f verificationReadFunc) ReadPasswordCredential(ctx context.Context, key CredentialKey) (CredentialSnapshot, error) {
	return f(ctx, key)
}

func verificationFixture(t *testing.T) (VerifierConfig, CredentialSnapshot, VerifyPasswordRequest) {
	t.Helper()
	w := testPasswordWork(t)
	secret, err := primitive.NewSecret([]byte("public-dummy-only"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Destroy)
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	ref := identity.CredentialRef{ID: "password-a", TenantID: "tenant-a", UserID: "user-a", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 2}
	snapshot, err := NewCredentialSnapshot(identity.CredentialAuthorityRecord{
		User:       identity.User{ID: "user-a", TenantID: "tenant-a", Status: identity.StatusActive, Version: 33},
		Credential: ref, AuthorityVersion: 7, Enabled: true, ExpiresAt: now.Add(time.Minute),
	}, w.dummy)
	if err != nil {
		t.Fatal(err)
	}
	config := VerifierConfig{Primitive: w.primitive, MaximumBytes: w.maximum, Timeout: time.Second, DummyHash: w.dummy, Now: func() time.Time { return now },
		Repository: verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) { return snapshot, nil })}
	return config, snapshot, VerifyPasswordRequest{TenantID: "tenant-a", SubjectID: "user-a", Password: secret, ExpectedVersion: 2}
}

func TestPublicPasswordVerifierMatchesOnlyCurrentPrimaryCredential(t *testing.T) {
	config, _, request := verificationFixture(t)
	service, err := NewPasswordVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	var contract PasswordVerifier = service
	got, err := contract.VerifyPassword(context.Background(), request)
	if err != nil || !got.Matched || got.CredentialVersion != 2 || got.NeedsRehash {
		t.Fatal("current canonical credential did not verify", err)
	}
	wrong, _ := primitive.NewSecret([]byte("wrong-public-test"))
	defer wrong.Destroy()
	request.Password = wrong
	got, err = contract.VerifyPassword(context.Background(), request)
	if err != nil || got != (PasswordVerification{}) {
		t.Fatal("mismatch was not neutral")
	}
}

func TestPublicPasswordVerifierDummyNeverMatches(t *testing.T) {
	config, _, request := verificationFixture(t)
	config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) {
		return CredentialSnapshot{}, ErrCredentialAbsent
	})
	service, err := NewPasswordVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []identity.UserID{"", "user-a"} {
		request.SubjectID = subject
		got, err := service.VerifyPassword(context.Background(), request)
		if err != nil || got != (PasswordVerification{}) {
			t.Fatal("matching dummy authenticated unknown account")
		}
	}
}

func TestPublicPasswordVerifierDeniesChangedAuthorityAndMaterial(t *testing.T) {
	for name, mutate := range map[string]func(*CredentialSnapshot){
		"blocked": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.User.Status = identity.StatusSuspended })
		},
		"disabled": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.Enabled = false })
		},
		"epoch": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.AuthorityVersion++ })
		},
		"credential": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.Credential.Version++ })
		},
		"tenant": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.Credential.TenantID = "other" })
		},
		"owner": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.Credential.Owner = "sso" })
		},
		"material": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.EncodedHash = primitive.EncodedHash{} })
		},
		"expired": func(s *CredentialSnapshot) {
			editVerificationSnapshot(s, func(r *credentialSnapshot) { r.Authority.ExpiresAt = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, snapshot, request := verificationFixture(t)
			reads := 0
			config.Repository = verificationReadFunc(func(ctx context.Context, key CredentialKey) (CredentialSnapshot, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded primary read")
				}
				if key.TenantID != request.TenantID || key.SubjectID != request.SubjectID {
					t.Fatal("lookup lost scope")
				}
				reads++
				if reads == 2 {
					mutate(&snapshot)
				}
				return snapshot, nil
			})
			service, err := NewPasswordVerifier(config)
			if err != nil {
				t.Fatal(err)
			}
			got, err := service.VerifyPassword(context.Background(), request)
			if err != nil || got != (PasswordVerification{}) {
				t.Fatal("changed authority produced match", err)
			}
		})
	}
}

func TestPublicPasswordVerifierFailureCancellationAndClock(t *testing.T) {
	config, _, request := verificationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) {
		cancel()
		return CredentialSnapshot{}, errors.New("private diagnostic")
	})
	service, err := NewPasswordVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.VerifyPassword(ctx, request)
	if got.Matched || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	config, snapshot, request := verificationFixture(t)
	config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) { panic("private diagnostic") })
	service, _ = NewPasswordVerifier(config)
	got, err = service.VerifyPassword(context.Background(), request)
	if got.Matched || !errors.Is(err, ErrPasswordWork) {
		t.Fatal("panic leaked")
	}
	config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) { return snapshot, nil })
	base := config.Now()
	calls := 0
	config.Now = func() time.Time {
		calls++
		if calls > 1 {
			return base.Add(-time.Second)
		}
		return base
	}
	service, _ = NewPasswordVerifier(config)
	got, err = service.VerifyPassword(context.Background(), request)
	if got.Matched || !errors.Is(err, ErrPasswordWork) {
		t.Fatal("regressed clock produced match")
	}
}

func TestPublicPasswordVerifierLateCancellationIncludesDummyPath(t *testing.T) {
	config, _, request := verificationFixture(t)
	request.SubjectID = ""
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := config.Now()
	calls := 0
	config.Now = func() time.Time {
		calls++
		if calls == 2 {
			cancel()
		}
		return now
	}
	service, err := NewPasswordVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.VerifyPassword(ctx, request)
	if got != (PasswordVerification{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("dummy completion swallowed late cancellation")
	}
}

func TestPublicPasswordVerifierRejectsIncompleteCompositionAndInput(t *testing.T) {
	config, _, request := verificationFixture(t)
	for _, mutate := range []func(*VerifierConfig){
		func(c *VerifierConfig) { c.Primitive = nil },
		func(c *VerifierConfig) { c.Repository = nil },
		func(c *VerifierConfig) { c.Now = nil },
		func(c *VerifierConfig) { c.MaximumBytes = 0 },
		func(c *VerifierConfig) { c.MaximumBytes = 129 },
		func(c *VerifierConfig) { c.Timeout = 0 },
		func(c *VerifierConfig) { c.Timeout = 11 * time.Second },
		func(c *VerifierConfig) { c.DummyHash = primitive.EncodedHash{} },
	} {
		bad := config
		mutate(&bad)
		if verifier, err := NewPasswordVerifier(bad); verifier != nil || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("invalid composition accepted")
		}
	}
	service, _ := NewPasswordVerifier(config)
	for _, mutate := range []func(*VerifyPasswordRequest){
		func(r *VerifyPasswordRequest) { r.TenantID = "" },
		func(r *VerifyPasswordRequest) { r.SubjectID = identity.UserID(strings.Repeat("x", 129)) },
		func(r *VerifyPasswordRequest) { r.Password = primitive.Secret{} },
	} {
		bad := request
		mutate(&bad)
		got, err := service.VerifyPassword(context.Background(), bad)
		if got.Matched || err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, service := range []*CredentialVerifier{nil, {}} {
		got, err := service.VerifyPassword(context.Background(), request)
		if got.Matched || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("zero verifier accepted")
		}
	}
	got, err := service.VerifyPassword(nil, request)
	if got.Matched || !errors.Is(err, ErrPasswordWork) {
		t.Fatal("nil context accepted")
	}
}

func TestPublicPasswordVerifierInitialStatusVersionAndTimeDenials(t *testing.T) {
	for _, status := range []identity.Status{identity.StatusSuspended, identity.StatusBanned, identity.StatusDeleted, identity.StatusAnonymized} {
		config, snapshot, request := verificationFixture(t)
		editVerificationSnapshot(&snapshot, func(r *credentialSnapshot) { r.Authority.User.Status = status })
		config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) { return snapshot, nil })
		service, _ := NewPasswordVerifier(config)
		got, err := service.VerifyPassword(context.Background(), request)
		if got != (PasswordVerification{}) || err != nil {
			t.Fatal("blocked account comparison was not neutral")
		}
	}
	config, _, request := verificationFixture(t)
	service, _ := NewPasswordVerifier(config)
	request.ExpectedVersion++
	got, err := service.VerifyPassword(context.Background(), request)
	if got != (PasswordVerification{}) || err != nil {
		t.Fatal("stale version accepted")
	}
	request.ExpectedVersion = 0
	got, err = service.VerifyPassword(context.Background(), request)
	if !got.Matched || err != nil {
		t.Fatal("omitted expected version denied")
	}
	base := config.Now()
	calls := 0
	config.Now = func() time.Time {
		calls++
		if calls > 1 {
			return base.Add(2 * time.Second)
		}
		return base
	}
	service, _ = NewPasswordVerifier(config)
	got, err = service.VerifyPassword(context.Background(), request)
	if got.Matched || !errors.Is(err, ErrPasswordWork) {
		t.Fatal("work budget expired but matched")
	}
}

func TestPasswordVerificationInputAndSnapshotDenySerialization(t *testing.T) {
	_, snapshot, request := verificationFixture(t)
	for _, input := range []any{snapshot, request} {
		if _, err := json.Marshal(input); err == nil {
			t.Fatal("sensitive value serialized")
		}
		if !strings.Contains(fmt.Sprintf("%+v", input), "redacted") {
			t.Fatal("diagnostics not redacted")
		}
	}
	wrapped := struct{ snapshot CredentialSnapshot }{snapshot}
	if strings.Contains(fmt.Sprintf("%+v", wrapped), snapshot.EncodedHash().String()) {
		t.Fatal("private diagnostic wrapper exposed credential hash")
	}
	for _, verb := range []string{"%s", "%q", "%d"} {
		if strings.Contains(fmt.Sprintf(verb, wrapped), snapshot.EncodedHash().String()) {
			t.Fatal("unsupported diagnostic verb exposed credential hash")
		}
	}
}

func TestPublicPasswordVerifierPerformsRealDummyWork(t *testing.T) {
	for _, subject := range []identity.UserID{"", "user-a"} {
		config, _, request := verificationFixture(t)
		request.SubjectID = subject
		observed := false
		service, err := primitive.New(config.Primitive.Policy(), primitive.WithObserver(workObservation(func(_ context.Context, event primitive.Observation) {
			observed = event.Operation == primitive.OperationVerify && event.Outcome == primitive.OutcomeSuccess
		})))
		if err != nil {
			t.Fatal(err)
		}
		config.Primitive = service
		config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) {
			return CredentialSnapshot{}, ErrCredentialAbsent
		})
		verifier, _ := NewPasswordVerifier(config)
		got, err := verifier.VerifyPassword(context.Background(), request)
		if err != nil || got.Matched || !observed {
			t.Fatal("unknown account skipped actual current-policy dummy comparison")
		}
	}
}

func TestPublicPasswordVerifierReportsUpgradeWithoutMutatingMaterial(t *testing.T) {
	config, snapshot, request := verificationFixture(t)
	legacyPolicy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Bcrypt, BcryptCost: 4, Limits: config.Primitive.Policy().Limits()})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := primitive.New(legacyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := legacy.Hash(context.Background(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = NewCredentialSnapshot(snapshot.Authority(), hash)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	request.Password = secret
	reads := 0
	config.Repository = verificationReadFunc(func(context.Context, CredentialKey) (CredentialSnapshot, error) {
		reads++
		projection := snapshot.Authority()
		projection.User.Version += uint64(reads)
		return NewCredentialSnapshot(projection, snapshot.EncodedHash())
	})
	verifier, err := NewPasswordVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.VerifyPassword(context.Background(), request)
	if err != nil || !got.Matched || !got.NeedsRehash || got.CredentialVersion != 2 || snapshot.EncodedHash().String() != hash.String() || secret.Len() != 1 {
		t.Fatal("legacy short credential upgrade advice or custody lost")
	}
}

func TestCredentialSnapshotConstructionAndProjectionIsolation(t *testing.T) {
	_, snapshot, _ := verificationFixture(t)
	authority := snapshot.Authority()
	authority.Credential.Version++
	if snapshot.Authority().Credential.Version != 2 {
		t.Fatal("projection changed retained snapshot")
	}
	if got, err := NewCredentialSnapshot(identity.CredentialAuthorityRecord{}, snapshot.EncodedHash()); got.custody != nil || !errors.Is(err, ErrPasswordWork) {
		t.Fatal("zero authority constructed")
	}
	if got, err := NewCredentialSnapshot(snapshot.Authority(), primitive.EncodedHash{}); got.custody != nil || !errors.Is(err, ErrPasswordWork) {
		t.Fatal("zero material constructed")
	}
	var zero CredentialSnapshot
	if zero.Authority() != (identity.CredentialAuthorityRecord{}) || zero.EncodedHash().String() != "" {
		t.Fatal("zero projections not safe")
	}
}
