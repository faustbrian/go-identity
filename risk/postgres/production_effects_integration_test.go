//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// One owned fresh database shares the exact production schema across selected
// risk workflows. The enclosing fixture owns database and global-role cleanup.
func productionRiskEffects(t *testing.T, ctx context.Context, db *sql.DB, installed *bool) (*auditpostgres.IdentityContributor, *identityoutbox.Contributor) {
	t.Helper()
	if !*installed {
		install, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer install.Rollback()
		if _, err = install.ExecContext(ctx, auditpostgres.FreshInstallPreflightSQL()); err != nil {
			t.Fatal("owned audit preflight", err)
		}
		for _, source := range []fs.FS{auditpostgres.Migrations(), outboxpostgres.Migrations(), identityoutbox.Migrations()} {
			files, err := fs.ReadDir(source, ".")
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				contents, err := fs.ReadFile(source, file.Name())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = install.ExecContext(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
					t.Fatal("production migration", file.Name(), err)
				}
			}
		}
		if err = install.Commit(); err != nil {
			t.Fatal(err)
		}
		*installed = true
	}
	a, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		t.Fatal(err)
	}
	o, err := identityoutbox.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	return a, o
}

// Fault only after the real participant has written its complete prefix. This
// distinguishes atomic rollback from a failure before any durable effect.
type captchaProductionAuditFailure struct {
	identitypostgres.AuditContributor
}

func (p captchaProductionAuditFailure) PersistAudits(ctx context.Context, w identitypostgres.Work) error {
	if err := p.AuditContributor.PersistAudits(ctx, w); err != nil {
		return err
	}
	return identity.UnavailableError{}
}
func (p captchaProductionAuditFailure) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return p.AuditContributor.(identitypostgres.RecoveryContributor).RecoverParticipant(ctx, w)
}

type captchaProductionOutboxFailure struct {
	identitypostgres.LifecycleContributor
}

func (p captchaProductionOutboxFailure) PersistLifecycle(ctx context.Context, w identitypostgres.Work) error {
	if err := p.LifecycleContributor.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	return identity.UnavailableError{}
}
func (p captchaProductionOutboxFailure) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return p.LifecycleContributor.(identitypostgres.RecoveryContributor).RecoverParticipant(ctx, w)
}

type captchaProductionEffects struct {
	audit     identitypostgres.AuditContributor
	lifecycle identitypostgres.LifecycleContributor
}
