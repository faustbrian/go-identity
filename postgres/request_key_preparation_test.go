package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestRequestKeyPreparationMigrationPreservesHistory(t *testing.T) {
	base := RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	upgrade := RequestKeyPreparationMigrationSource{Base: base, Version: 11}
	history, err := upgrade.Load(context.Background())
	if err != nil || len(history) != len(original)+1 || history[len(original)].DownSQL() != "" {
		t.Fatal("invalid forward migration", err)
	}
	for i, m := range original {
		if history[i] != m {
			t.Fatal("installed history rewritten")
		}
	}
	for _, bad := range []RequestKeyPreparationMigrationSource{{}, {Base: base, Version: 10}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid history accepted")
		}
	}
	if h, err := upgrade.Load(nil); err == nil || h != nil {
		t.Fatal("nil migration context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := upgrade.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancelled history returned")
	}
}

type requestPreparationParticipant struct {
	scopeFeatureParticipant
	prepare func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error)
}

func (p *requestPreparationParticipant) PrepareRequestKey(ctx context.Context, b RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	return p.prepare(ctx, b, intent)
}

func TestRequestKeyPreparationRequiresExactRegisteredOwner(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	s, _ := command.Feature()
	owner := &requestPreparationParticipant{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	plan.Feature.Contributor = owner.Descriptor()
	c := &Coordinator{registry: registry}
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", Method: "POST", RouteID: s.Operation.OperationID}
	if err := c.validateRequestPreparation(scope, *plan.Feature, owner); err != nil {
		t.Fatal("exact owner rejected", err)
	}
	foreign := &requestPreparationParticipant{scopeFeatureParticipant: owner.scopeFeatureParticipant}
	for _, bad := range []RequestKeyPreparationContributor{nil, foreign} {
		if err := c.validateRequestPreparation(scope, *plan.Feature, bad); err == nil {
			t.Fatal("unregistered preparation owner accepted")
		}
	}
	scope.RouteID = "identity.other.send"
	if err := c.validateRequestPreparation(scope, *plan.Feature, owner); err == nil {
		t.Fatal("cross-route preparation admitted")
	}
}

func TestRequestKeyPreparationCallbackBoundsAndRedaction(t *testing.T) {
	intent, _ := identity.NewRequestIntent(nil)
	for name, callback := range map[string]func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error){
		"empty": func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
			return nil, nil
		},
		"oversized": func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
			return make([]byte, 1048577), nil
		},
		"private error": func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
			return []byte{1}, errors.New("private-diagnostic")
		},
		"panic": func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
			panic("private-diagnostic")
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &requestPreparationParticipant{prepare: callback}
			wire, err := generateRequestPreparation(context.Background(), p, RequestKeyPreparationBinding{}, intent)
			if err == nil || wire != nil || err.Error() == "private-diagnostic" {
				t.Fatal("unsafe preparation returned usable custody")
			}
		})
	}
	wire := []byte{1, 2, 3}
	p := &requestPreparationParticipant{prepare: func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
		return wire, nil
	}}
	got, err := generateRequestPreparation(context.Background(), p, RequestKeyPreparationBinding{}, intent)
	if err != nil || len(got) != 3 {
		t.Fatal("valid ciphertext rejected", err)
	}
	got[0] = 4
	if wire[0] != 1 {
		t.Fatal("borrowed output retained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.prepare = func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
		t.Fatal("cancelled callback invoked")
		return nil, nil
	}
	if got, err := generateRequestPreparation(ctx, p, RequestKeyPreparationBinding{}, intent); err == nil || got != nil {
		t.Fatal("cancelled preparation accepted")
	}
}
