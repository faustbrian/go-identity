package postgres

import (
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProxyRetirementDrainMigrationIsAdditive(t *testing.T) {
	history, err := (ProxyRetirementDrainMigrationSource{Schema: "oauth_rp", Version: 94}).Load(t.Context())
	if err != nil || len(history) != 1 || history[0].Version() != 94 || history[0].DownSQL() != "" {
		t.Fatal("drain must have one optional forward migration", err)
	}
	sql := history[0].UpSQL()
	if !strings.Contains(sql, "PRIMARY KEY(tenant_id,cascade_id,generation,role,deployment)") || strings.Contains(sql, "ALTER TABLE") {
		t.Fatal("the migration must only create a generation-scoped checkpoint store")
	}
	if _, err := (ProxyRetirementDrainMigrationSource{Schema: "audit", Version: 94}).Load(t.Context()); err == nil {
		t.Fatal("accepted a reserved namespace")
	}
}

func TestProxyRetirementDrainAcceptsOnlyDefinitiveExactOriginalResult(t *testing.T) {
	const tenant identity.TenantID = "retirement-tenant"
	target := proxyRetirementDrainTarget{
		Command: "AQEBAQEBAQEBAQEBAQEBAQ",
		Flow:    "AgICAgICAgICAgICAgICAg",
		Origin:  "AwMDAwMDAwMDAwMDAwMDAw",
	}
	operation := kernel.OAuthProxyOriginRetirementOperation()
	noChange := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: target.Command, TenantID: tenant, ActorID: "retirement-service", ActorKind: authorization.SubjectServiceAccount,
			AnonymousFlowID: string(target.Flow), RecordID: string(target.Flow), CorrelationID: string(target.Origin),
			OperationID: operation.OperationID, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion,
			PolicyID: "retirement-policy", PolicyVersion: 1,
		},
		Outcome: identity.CommitOutcomeNotCommitted,
		Feature: &identity.FeatureReceipt{Operation: operation},
	}
	if err := noChange.Validate(); err != nil {
		t.Fatal("invalid definitive fixture", err)
	}
	alreadyRetired := kernel.TypedFeatureFailureError{Code: kernel.FeatureFailureOAuthProxyAlreadyRetired}
	committed := noChange
	committed.Outcome, committed.AuditEventID = identity.CommitOutcomeCommitted, "retirement-audit"
	committed.Feature = &identity.FeatureReceipt{Operation: operation, AfterVersion: 1}
	unknown := noChange
	unknown.Outcome = identity.CommitOutcomeUnknown
	wrongCommand := noChange
	wrongCommand.Binding.CommandID = "BAQEBAQEBAQEBAQEBAQEBA"
	wrongOrigin := noChange
	wrongOrigin.Binding.CorrelationID = "BAQEBAQEBAQEBAQEBAQEBA"
	wrongTenant := noChange
	wrongTenant.Binding.TenantID = "foreign-tenant"
	wrongOwner := noChange
	wrongOperation := operation
	wrongOperation.Owner = "foreign-feature"
	wrongOwner.Feature = &identity.FeatureReceipt{Operation: wrongOperation}
	for _, tc := range []struct {
		name   string
		result identity.CommandResult
		err    error
		want   bool
	}{
		{"original committed", committed, nil, true},
		{"native already retired", noChange, alreadyRetired, true},
		{"committed with error", committed, alreadyRetired, false},
		{"unknown with typed detail", unknown, alreadyRetired, false},
		{"wrong command", wrongCommand, alreadyRetired, false},
		{"wrong origin", wrongOrigin, alreadyRetired, false},
		{"wrong tenant", wrongTenant, alreadyRetired, false},
		{"wrong feature owner", wrongOwner, alreadyRetired, false},
		{"no terminal", identity.CommandResult{}, alreadyRetired, false},
		{"ordinary conflict", noChange, identity.ConflictError{}, false},
		{"ordinary denial", noChange, identity.ForbiddenError{}, false},
		{"unrelated typed detail", noChange, kernel.TypedFeatureFailureError{Code: kernel.FeatureFailureConflict}, false},
		{"no terminal detail", noChange, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := confirmedProxyRetirementDrainResult(tc.result, tc.err, tenant, target); got != tc.want {
				t.Fatalf("confirmed = %t, want %t", got, tc.want)
			}
		})
	}
}
