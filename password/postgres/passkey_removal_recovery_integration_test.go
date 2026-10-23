//go:build integration

package passwordpostgres

import (
	"context"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// The controlled native domain exercises only this password-owned recovery
// guard under a real coordinator. It does not prove passkey deletion or fresh
// proof. Its reset owner and account/material come from the genuine reset
// request/completion journey, not private constructor fields or fake stores.
type passkeyRecoveryProbe struct {
	organizationPrimaryWorkFixture
	source             *PasskeyRemovalRecoverySource
	mode               string
	attempted, allowed bool
}

func (p *passkeyRecoveryProbe) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	bind, _ := c.Feature()
	b := bind.Binding
	var sql string
	switch p.mode {
	case "material-absent":
		sql = `DELETE FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2`
	case "material-stale":
		sql = `UPDATE identity_password.credentials SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`
	case "material-corrupt":
		sql = `UPDATE identity_password.credentials SET encoded_hash='invalid' WHERE tenant_id=$1 AND user_id=$2`
	case "password-disabled":
		sql = `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND kind=1 AND owner='identity/password'`
	case "password-expired":
		sql = `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2 AND kind=1 AND owner='identity/password'`
	case "email-unverified":
		sql = `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`
	case "user-blocked":
		sql = `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`
	}
	if sql != "" {
		if _, err := w.Exec(ctx, sql, string(b.TenantID), string(b.UserID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.attempted = true
	if err := p.source.CheckPasskeyRemovalRecovery(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.allowed = true
	if p.mode != "commit" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: 1, AfterVersion: 2}, nil
}
func (p *passkeyRecoveryProbe) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.source.CheckPasskeyRemovalRecovery(ctx, w, p, c)
}

func testPasskeyRemovalRecoveryOwner(t *testing.T, ctx context.Context, reset *ResetService, canonical string) {
	t.Helper()
	source, err := NewPasskeyRemovalRecoverySource(reset)
	if err != nil {
		t.Fatal("actual selected recovery source", err)
	}
	c := reset.config()
	profile := sessionpg.SessionServiceConfig{Repository: c.Session, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: c.GlobalAuthorityID, PolicyNamespace: c.AuthorizationNamespace, Audience: "identity", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}}
	if !source.Matches(reset.pool, profile, c.PolicyID, c.Coordinator.AdmissionPolicy.PolicyVersion) {
		t.Fatal("real reset realm refused")
	}
	for _, mode := range []string{"realm", "namespace", "schema", "policy", "revision", "pool"} {
		changed, policy, version, pool := profile, c.PolicyID, c.Coordinator.AdmissionPolicy.PolicyVersion, reset.pool
		switch mode {
		case "realm":
			changed.Profile.GlobalAuthorityID = "foreign"
		case "namespace":
			changed.Profile.PolicyNamespace = "foreign"
		case "schema":
			changed.Repository.Schema = "foreign"
		case "policy":
			policy = "foreign"
		case "revision":
			version++
		case "pool":
			pool = nil
		}
		if source.Matches(pool, changed, policy, version) {
			t.Fatal("foreign recovery composition admitted", mode)
		}
	}
	var user string
	if err := reset.pool.Raw().QueryRow(ctx, `SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND kind='email' AND canonical_value=$2`, string(signinTestTenant), canonical).Scan(&user); err != nil {
		t.Fatal("genuine recovery account", err)
	}
	for _, mode := range []string{"commit", "material-absent", "material-stale", "material-corrupt", "password-disabled", "password-expired", "email-unverified", "user-blocked", "wrong-profile"} {
		t.Run(mode, func(t *testing.T) {
			p := &passkeyRecoveryProbe{source: source, mode: mode}
			p.op = actionPrimaryOperation("identity.passkey.delete")
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			reference, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			b := identity.CommandBinding{CommandID: id, TenantID: signinTestTenant, UserID: identity.UserID(user), ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, RecordID: string(reference), OperationID: p.op.OperationID, SchemaID: p.op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(id)}
			fields, err := source.Fields()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-profile" {
				fields[0].Value.Bytes[0] ^= 1
			}
			p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: p.op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
			if err != nil {
				t.Fatal(err)
			}
			outbox, err := lifecyclepg.NewContributor()
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{reset.directory, audits, outbox, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(reset.pool, registry, c.Coordinator)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := resetServiceAuditDeclaration(b, p.op, registry.Descriptors(), "credential", 1, 2, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			plan.Feature.Contributor = p.Descriptor()
			plan.Lifecycle.EventType = "identity.passkey.remove_credential"
			plan, err = coordinator.PrepareCommandPlan(b, p.command, plan)
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, w, p.command)
			if applyErr != nil {
				result, err = coordinator.Abort(w, applyErr)
			} else {
				result, err = coordinator.Commit(w, result)
			}
			if !p.attempted {
				t.Fatal("recovery test did not reach real owner", applyErr, err)
			}
			if mode == "commit" {
				if err != nil || !p.allowed || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("usable actual recovery path refused", applyErr, err)
				}
			} else if p.allowed || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("withdrawn or corrupt recovery path admitted", mode)
			}
		})
	}
}
