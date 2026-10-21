package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func TestAnonymousSelectionRequiresConcreteOwnersAndIsOptIn(t *testing.T) {
	for _, feature := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true, anonymous: &anonymousState{}}}}} {
		if owner, err := feature.AnonymousPreAuth(); err == nil || owner != nil {
			t.Fatal("unselected anonymous initiation exported an owner")
		}
	}
	if owner, err := composeAnonymous(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}, nil); err != nil || owner != nil {
		t.Fatal("unselected anonymous behavior acquired an owner")
	}
	if owner, err := composeAnonymous(StoreConfiguration{Anonymous: &AnonymousConfiguration{}}, ReferenceDependencies{}, risk.Evaluator{}, nil); err == nil || owner != nil {
		t.Fatal("anonymous selection accepted absent native dependencies")
	}
	if owner, err := composeAnonymousHTTP(StoreConfiguration{}, nil, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected anonymous transport acquired owners")
	}
	if owner, err := composeAnonymousHTTP(StoreConfiguration{HTTPAnonymous: &HTTPAnonymousConfiguration{Signin: true}}, nil, nil, nil); err == nil || owner != nil {
		t.Fatal("anonymous HTTP selection accepted missing native/device/rate owners")
	}
}

// This verifies graph custody only. Native PostgreSQL behavior is exercised by
// the public HTTP journey, not by these deliberately absent native owners.
func TestAnonymousPublicHandleRetainsSelectionTenantAndGraphLifetime(t *testing.T) {
	for _, features := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}, {state: &storeState{closed: true, features: &featureState{composed: true, anonymous: &anonymousState{}}}}} {
		if owner, err := features.Anonymous(); err == nil || owner != nil {
			t.Fatal("unselected or closed graph exported an anonymous owner")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant-a": {}}, features: &featureState{composed: true, timeout: time.Second, anonymous: &anonymousState{}}}
	owner, err := (FeatureSet{state: state}).Anonymous()
	if err != nil || owner == nil {
		t.Fatal("selected graph could not expose native handle", err)
	}
	deny := func() {
		t.Helper()
		for _, call := range []func() error{
			func() error {
				_, err := owner.Signin(t.Context(), anonymous.SigninRequest{TenantID: "tenant-a"})
				return err
			},
			func() error { _, err := owner.Get(t.Context(), session.GetRequest{TenantID: "tenant-a"}); return err },
			func() error {
				_, err := owner.Delete(t.Context(), anonymous.DeletionRequest{TenantID: "tenant-a"})
				return err
			},
			func() error {
				_, err := owner.Upgrade(t.Context(), anonymous.UpgradeRequest{TenantID: "tenant-a"})
				return err
			},
			func() error {
				_, err := owner.RecoverSignin(t.Context(), anonymous.SigninRecoveryRequest{})
				return err
			},
			func() error {
				_, err := owner.RecoverDeletion(t.Context(), anonymous.DeletionRecoveryRequest{Recovery: identity.RecoveryQuery{TenantID: "tenant-a"}})
				return err
			},
			func() error {
				_, err := owner.RecoverUpgrade(t.Context(), anonymous.UpgradeRecoveryRequest{Recovery: identity.RecoveryQuery{TenantID: "tenant-a"}})
				return err
			},
		} {
			if call() == nil {
				t.Fatal("inactive graph or unselected native operation granted access")
			}
		}
	}
	deny() // Before initialization.
	state.features.ready = true
	deny() // No missing native variant may be substituted by another owner.
	if _, _, _, err := owner.enter(t.Context(), "foreign"); err == nil || state.active != 0 {
		t.Fatal("foreign tenant entered or retained graph work")
	}
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if _, err := owner.Get(ctx, session.GetRequest{TenantID: "tenant-a"}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller lost original cancellation", err)
	}
	bounded, done, _, err := owner.enter(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if deadline, ok := bounded.Deadline(); !ok || time.Until(deadline) > time.Second || state.active != 1 {
		t.Fatal("native handle lost bounded tracked graph custody")
	}
	cancel()
	select {
	case <-bounded.Done():
	case <-time.After(time.Second):
		t.Fatal("graph shutdown failed to cancel retained native call")
	}
	done()
	if state.active != 0 {
		t.Fatal("native handle did not drain graph work")
	}
	state.closed = true
	deny()
	if _, err := json.Marshal(owner); !errors.Is(err, anonymous.ErrDisclosure) || fmt.Sprintf("%#v", owner) != "reference.AnonymousService(redacted)" {
		t.Fatal("native handle disclosed graph custody")
	}
	var zero AnonymousService
	if _, err := zero.Get(t.Context(), session.GetRequest{}); err == nil {
		t.Fatal("zero native handle granted access")
	}
}
