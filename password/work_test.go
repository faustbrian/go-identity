package password

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	primitive "github.com/faustbrian/go-password/v2"
)

func testPasswordWork(t *testing.T) passwordWork {
	t.Helper()
	policy, err := primitive.NewPolicy(primitive.PolicyConfig{
		Algorithm: primitive.Argon2id,
		Argon2id:  primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16},
		Limits:    primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := primitive.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := service.Hash(context.Background(), []byte("public-dummy-only"))
	if err != nil {
		t.Fatal(err)
	}
	return passwordWork{primitive: service, minimum: 4, maximum: 128, timeout: time.Second, dummy: dummy}
}

func TestNewPasswordHashRequiresCompletedScreening(t *testing.T) {
	w := testPasswordWork(t)
	secret, err := primitive.NewSecret([]byte(" untouched public-test "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	denied := errors.New("private provider diagnostic")
	for _, screen := range []func(context.Context, primitive.Secret) error{nil, func(context.Context, primitive.Secret) error { return denied }} {
		hash, err := w.newHash(context.Background(), secret, screen)
		if hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("unscreened candidate produced hash")
		}
		if err != nil && bytes.Contains([]byte(err.Error()), []byte("diagnostic")) {
			t.Fatal("screening diagnostic leaked")
		}
	}
	hash, err := w.newHash(context.Background(), secret, func(ctx context.Context, candidate primitive.Secret) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("screening has no deadline")
		}
		return candidate.Use(func(raw []byte) error {
			if string(raw) != " untouched public-test " {
				t.Fatal("screening changed bytes")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	matched, err := w.primitive.Verify(context.Background(), []byte(" untouched public-test "), hash.String())
	if err != nil || !matched.Match() {
		t.Fatal("hash did not preserve screened candidate")
	}
	if secret.Len() == 0 {
		t.Fatal("hash destroyed caller custody")
	}
}

func TestPasswordVerificationNeverAuthenticatesDummy(t *testing.T) {
	w := testPasswordWork(t)
	secret, _ := primitive.NewSecret([]byte("public-dummy-only"))
	defer secret.Destroy()
	result, err := w.verify(context.Background(), secret, primitive.EncodedHash{}, false)
	if err != nil || result.Match() || result.NeedsRehash() {
		t.Fatal("unknown account authenticated matching dummy")
	}
	result, err = w.verify(context.Background(), secret, w.dummy, true)
	if err != nil || !result.Match() {
		t.Fatal("known matching password denied")
	}
	wrong, _ := primitive.NewSecret([]byte("wrong-public-test"))
	defer wrong.Destroy()
	result, err = w.verify(context.Background(), wrong, w.dummy, true)
	if err != nil || result.Match() {
		t.Fatal("mismatch was not enumeration-neutral")
	}
	result, err = w.verify(context.Background(), secret, primitive.EncodedHash{}, true)
	if !errors.Is(err, ErrPasswordWork) || result.Match() {
		t.Fatal("corrupt known hash authenticated")
	}
}

func TestPasswordWorkCancellationAndDestructionDiscardOutput(t *testing.T) {
	w := testPasswordWork(t)
	secret, _ := primitive.NewSecret([]byte("public-test"))
	defer secret.Destroy()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hash, err := w.newHash(ctx, secret, func(context.Context, primitive.Secret) error { t.Fatal("canceled screening ran"); return nil })
	if hash.String() != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	result, err := w.verify(ctx, secret, w.dummy, true)
	if result.Match() || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled verification returned match")
	}
	hash, err = w.newHash(context.Background(), secret, func(context.Context, primitive.Secret) error { secret.Destroy(); return nil })
	if hash.String() != "" || !errors.Is(err, ErrInvalidPassword) {
		t.Fatal("destroyed screened password produced hash")
	}
	result, err = w.verify(context.Background(), secret, w.dummy, true)
	if result.Match() || !errors.Is(err, ErrInvalidPassword) {
		t.Fatal("destroyed secret authenticated")
	}
}

func TestPasswordScreeningPrecedesHashingAndCannotLeakPanic(t *testing.T) {
	w := testPasswordWork(t)
	admission, err := primitive.NewAdmission(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := admission.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	hashCalls := 0
	service, err := primitive.New(w.primitive.Policy(), primitive.WithAdmission(admission), primitive.WithObserver(workObservation(func(_ context.Context, event primitive.Observation) {
		if event.Operation == primitive.OperationHash {
			hashCalls++
		}
	})))
	if err != nil {
		t.Fatal(err)
	}
	w.primitive = service
	secret, _ := primitive.NewSecret([]byte("public-test"))
	defer secret.Destroy()
	for _, screen := range []func(context.Context, primitive.Secret) error{
		func(context.Context, primitive.Secret) error { return errors.New("private diagnostic") },
		func(context.Context, primitive.Secret) error { panic("private diagnostic") },
	} {
		hash, err := w.newHash(context.Background(), secret, screen)
		if hash.String() != "" || !errors.Is(err, ErrPasswordWork) || hashCalls != 0 {
			t.Fatal("hashing ran before successful screening")
		}
	}
	hash, err := w.newHash(context.Background(), secret, func(context.Context, primitive.Secret) error { return nil })
	if hash.String() != "" || !errors.Is(err, ErrPasswordWork) || hashCalls != 1 {
		t.Fatal("primitive admission failure yielded hash or skipped work")
	}
}

func TestPasswordWorkRejectsInvalidConfigurationAndLateCancellation(t *testing.T) {
	w := testPasswordWork(t)
	secret, _ := primitive.NewSecret([]byte("public-test"))
	defer secret.Destroy()
	bad := []passwordWork{{}}
	for _, mutate := range []func(*passwordWork){
		func(w *passwordWork) { w.minimum = 0 },
		func(w *passwordWork) { w.maximum = 3 },
		func(w *passwordWork) { w.maximum = 129 },
		func(w *passwordWork) { w.timeout = 0 },
		func(w *passwordWork) { w.timeout = time.Minute + 1 },
		func(w *passwordWork) { w.dummy = primitive.EncodedHash{} },
	} {
		copy := w
		mutate(&copy)
		bad = append(bad, copy)
	}
	for _, invalid := range bad {
		if _, err := invalid.newHash(context.Background(), secret, func(context.Context, primitive.Secret) error { t.Fatal("invalid configuration screened"); return nil }); !errors.Is(err, ErrPasswordWork) {
			t.Fatal("invalid configuration admitted")
		}
		if result, err := invalid.verify(context.Background(), secret, w.dummy, true); result.Match() || !errors.Is(err, ErrPasswordWork) {
			t.Fatal("invalid verification configuration admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hash, err := w.newHash(ctx, secret, func(context.Context, primitive.Secret) error { cancel(); return nil })
	if hash.String() != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation produced hash")
	}
	if _, err := w.newHash(nil, secret, func(context.Context, primitive.Secret) error { return nil }); !errors.Is(err, ErrPasswordWork) {
		t.Fatal("nil context admitted")
	}
	if _, err := w.verify(nil, secret, w.dummy, true); !errors.Is(err, ErrPasswordWork) {
		t.Fatal("nil verification context admitted")
	}
}

func TestPasswordVerificationPreservesExistingShortCredentials(t *testing.T) {
	w := testPasswordWork(t)
	hash, err := w.primitive.Hash(context.Background(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := primitive.NewSecret([]byte("x"))
	defer secret.Destroy()
	result, err := w.verify(context.Background(), secret, hash, true)
	if err != nil || !result.Match() {
		t.Fatal("new signup minimum blocked existing password")
	}
	if _, err := w.newHash(context.Background(), secret, func(context.Context, primitive.Secret) error { t.Fatal("short candidate screened"); return nil }); !errors.Is(err, ErrInvalidPassword) {
		t.Fatal("short new password admitted")
	}
}

type workObservation func(context.Context, primitive.Observation)

func (f workObservation) Observe(ctx context.Context, event primitive.Observation) { f(ctx, event) }

func TestUnknownPasswordPerformsActualDummyVerification(t *testing.T) {
	w := testPasswordWork(t)
	var observations []primitive.Observation
	service, err := primitive.New(w.primitive.Policy(), primitive.WithObserver(workObservation(func(_ context.Context, event primitive.Observation) { observations = append(observations, event) })))
	if err != nil {
		t.Fatal(err)
	}
	w.primitive = service
	secret, _ := primitive.NewSecret([]byte("public-dummy-only"))
	defer secret.Destroy()
	result, err := w.verify(context.Background(), secret, primitive.EncodedHash{}, false)
	if err != nil || result.Match() || len(observations) != 1 || observations[0].Operation != primitive.OperationVerify || observations[0].Outcome != primitive.OutcomeSuccess {
		t.Fatal("unknown account skipped real matching dummy work")
	}
}

func TestPasswordWorkDiscardsLatePrimitiveSuccess(t *testing.T) {
	for _, operation := range []string{"hash", "verify"} {
		for _, interruption := range []string{"cancel", "destroy"} {
			t.Run(operation+"/"+interruption, func(t *testing.T) {
				w := testPasswordWork(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				secret, _ := primitive.NewSecret([]byte("public-dummy-only"))
				defer secret.Destroy()
				service, err := primitive.New(w.primitive.Policy(), primitive.WithObserver(workObservation(func(_ context.Context, event primitive.Observation) {
					if event.Outcome != primitive.OutcomeSuccess {
						t.Fatal("fixture missed primitive success")
					}
					if interruption == "cancel" {
						cancel()
					} else {
						secret.Destroy()
					}
				})))
				if err != nil {
					t.Fatal(err)
				}
				w.primitive = service
				if operation == "hash" {
					hash, err := w.newHash(ctx, secret, func(context.Context, primitive.Secret) error { return nil })
					if hash.String() != "" || err == nil {
						t.Fatal("late interruption disclosed hash")
					}
				} else {
					result, err := w.verify(ctx, secret, w.dummy, true)
					if result.Match() || err == nil {
						t.Fatal("late interruption disclosed match")
					}
				}
			})
		}
	}
}

func TestPasswordWorkRejectsNonCurrentDummyProfiles(t *testing.T) {
	base := testPasswordWork(t)
	limits := base.primitive.Policy().Limits()
	strong, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 2, MemoryKiB: 16, Parallelism: 1, SaltLength: 16, OutputLength: 16}, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	strongService, err := primitive.New(strong)
	if err != nil {
		t.Fatal(err)
	}
	strongHash, err := strongService.Hash(context.Background(), []byte("public-dummy-only"))
	if err != nil {
		t.Fatal(err)
	}
	bcryptPolicy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Bcrypt, BcryptCost: 4, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	bcryptService, err := primitive.New(bcryptPolicy)
	if err != nil {
		t.Fatal(err)
	}
	mixedPolicy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 16, OutputLength: 16}, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	mixedService, err := primitive.New(mixedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	mixedHash, err := mixedService.Hash(context.Background(), []byte("public-dummy-only"))
	if err != nil {
		t.Fatal(err)
	}
	targetPolicy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 2, MemoryKiB: 16, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	targetService, err := primitive.New(targetPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*passwordWork){
		"stronger":              func(w *passwordWork) { w.dummy = strongHash },
		"different-algorithm":   func(w *passwordWork) { w.primitive = bcryptService },
		"mixed-stronger-weaker": func(w *passwordWork) { w.primitive = targetService; w.dummy = mixedHash },
	} {
		t.Run(name, func(t *testing.T) {
			w := base
			mutate(&w)
			secret, _ := primitive.NewSecret([]byte("public-dummy-only"))
			defer secret.Destroy()
			hash, err := w.newHash(context.Background(), secret, func(context.Context, primitive.Secret) error { return nil })
			if hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
				t.Fatal("non-current dummy profile admitted password work")
			}
			result, err := w.verify(context.Background(), secret, primitive.EncodedHash{}, false)
			if result.Match() || !errors.Is(err, ErrPasswordWork) {
				t.Fatal("non-current dummy used for unknown identity")
			}
		})
	}
}
