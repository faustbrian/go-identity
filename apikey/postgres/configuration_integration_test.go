//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
)

func TestConfigurationCheckIsReadOnlyAndCannotResetExistingAuthority(t *testing.T) {
	f := setupNativeConsumer(t)
	s, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckConfiguration(nil, baselineTenant); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("configuration check accepted a nil context")
	}
	if err := s.CheckConfiguration(f.ctx, baselineTenant); err == nil {
		t.Fatal("absent configuration was reported installed")
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.configurations`).Scan(&count); err != nil || count != 0 {
		t.Fatal("configuration check provisioned authority")
	}
	if err := s.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal("exact installed native configuration rejected", err)
	}
	different := f.config
	spec := different.Configuration.Spec()
	spec.Revision++
	different.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	other, err := apikeypg.NewService(f.pool, different)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.CheckConfiguration(f.ctx, baselineTenant); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("configuration check accepted different immutable profile", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=false,authority_version=2 WHERE tenant_id=$1`, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckConfiguration(f.ctx, baselineTenant); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("disabled configuration passed startup check", err)
	}
	var conflict identity.ConflictError
	if err := s.InitializeConfiguration(f.ctx, baselineTenant); !errors.As(err, &conflict) {
		t.Fatal("provisioning overwrote existing disabled authority", err)
	}
	var enabled bool
	var version string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT enabled,authority_version::text FROM identity_api_keys.configurations WHERE tenant_id=$1`, baselineTenant).Scan(&enabled, &version); err != nil || enabled || version != "2" {
		t.Fatal("configuration observation reset existing lifecycle")
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := s.CheckConfiguration(canceled, baselineTenant); !errors.Is(err, context.Canceled) {
		t.Fatal("configuration check ignored cancellation", err)
	}
}
