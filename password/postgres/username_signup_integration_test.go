//go:build integration

package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/username"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func testPublicUsernameRegistration(t *testing.T, ctx context.Context, pool *database.Pool, service *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
	t.Helper()
	for index, source := range []migrations.Source{
		kernel.UsernameRegistrationMigrationSource{Base: kernel.EmailVerificationMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.MigrationSource{}, Version: 27}, Version: 28}, Version: 29},
		mfapg.UsernameSignupMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if index == 0 && m.Version() >= 27 || index == 1 && m.Version() == 2 {
				if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
					t.Fatal("username owning forward history", err)
				}
			}
		}
	}
	r := fresh("username-signup@example.test", 'U')
	// Replacing caller-owned policy storage after construction must not replace
	// the native service's frozen enrollment rules under the same configuration.
	originalPolicy := *c.Username
	replacementSpec := username.ReferencePolicySpec()
	replacementSpec.Validators = []username.Validator{func(context.Context, username.Name) error { return username.ErrValidation }}
	replacement, err := username.NewPolicy(replacementSpec)
	if err != nil {
		t.Fatal(err)
	}
	*c.Username = *replacement
	result, err := service.Signup(ctx, r)
	*c.Username = originalPolicy
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || !result.VerificationRequired || result.SubjectID != "" || result.SessionID != "" {
		_, _, recoveryErr := result.Recovery.Bindings()
		t.Logf("username failure phase: recovery-prepared=%t outcome=%d", recoveryErr == nil, result.Outcome)
		t.Fatal("native username registration did not commit neutral verification outcome", err)
	}
	q, _, err := result.Recovery.Bindings()
	if err != nil || q.OperationID != "identity.username.signup" {
		t.Fatal("signup recovery relabeled original username action", err)
	}
	var canonical, display, profile, purpose string
	var version uint32
	var names, material, messages, factors int
	if err := pool.Raw().QueryRow(ctx, `SELECT i.canonical_value,i.display_value,i.normalization_profile,i.normalization_version::bigint,r.purpose,
 (SELECT count(*) FROM identity.identifiers WHERE tenant_id=r.tenant_id AND user_id=r.user_id),
 (SELECT count(*) FROM identity_password.credentials WHERE tenant_id=r.tenant_id AND user_id=r.user_id),
 (SELECT count(*) FROM identity.delivery_intents WHERE command_id=r.command_id),
 (SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=r.tenant_id AND user_id=r.user_id AND active_factors=0 AND initialized_purpose=r.purpose)
 FROM identity.registration_bindings r JOIN identity.identifiers i ON i.tenant_id=r.tenant_id AND i.user_id=r.user_id AND i.kind='username'
 WHERE r.command_id=$1`, base64Command(t, result.Recovery)).Scan(&canonical, &display, &profile, &version, &purpose, &names, &material, &messages, &factors); err != nil || canonical != "strasse" || display != "Straße" || profile != "identity.username.latin-v1" || version != 1 || purpose != q.OperationID || names != 2 || material != 1 || messages != 1 || factors != 1 {
		t.Fatal("username/email/password/verification/factor effects were not one original registration", err)
	}
	for _, spelling := range []string{"STRASSE", "different-name"} {
		changed := r
		changed.Username = spelling
		_, err := service.Signup(ctx, changed)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatal("same retry key remapped exact original username", err)
		}
	}
	again, err := service.Signup(ctx, r)
	if err != nil || !again.Replayed || again.Recovery != result.Recovery {
		t.Fatal("username replay did not retain original outcome", err)
	}
	occupied := fresh("username-other@example.test", 'V')
	occupied.Username = "STRASSE"
	neutral, err := service.Signup(ctx, occupied)
	if err != nil || neutral.Outcome != identity.CommitOutcomeCommitted || !neutral.VerificationRequired || neutral.SubjectID != "" {
		t.Fatal("canonical username collision lost neutral outcome", err)
	}
	var accounts int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND kind='email' AND canonical_value=$2`, string(r.TenantID), string(occupied.Email)).Scan(&accounts); err != nil || accounts != 0 {
		t.Fatal("occupied username left a partial account", err)
	}
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)); err != nil {
		t.Fatal(err)
	}
	testPublicUsernamePasswordSignin(t, ctx, pool, c, r, false)
	testPublicSignupVerificationOrigin(t, ctx, service, c, r, q.CommandID, keys)
	testPublicUsernamePasswordSignin(t, ctx, pool, c, r, true)
	t.Run("native username availability", func(t *testing.T) { testNativeUsernameAvailability(t, ctx, pool, c, r) })
}
