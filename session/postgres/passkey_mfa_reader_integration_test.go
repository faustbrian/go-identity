//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// The mapping port is the deliberate component seam; real session/kernel and
// confirmed TOTP authority are read from primary PostgreSQL. This is not proof
// of an assertion or an authenticated native passkey-to-factor completion.
type mfaPasskeyMappingComponent struct {
	version uint64
	now     time.Time
}

// Real owned revocation/audit/outbox; only RP mapping and policy use the same
// explicitly declared component seams as the preceding completion fixture.
func testPasskeyMFARevoke(t *testing.T, ctx context.Context, pool *database.Pool, config Config, profile MagicLinkAdmissionConfig, trustedClock clock.Clock, reader *session.SessionService, admitted session.GetResult, input session.GetRequest, selected *mfaPasskeySessionSelection) {
	t.Helper()
	selection := MFAPasskeySessionAdmission{Profile: selected.profile, Authority: selected.authority}
	execution := IssueExecutorConfig{Repository: config, Profile: IssueAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, Authorization: revokeQueryPolicy{}, Clock: trustedClock, PolicyID: revokeBinding().PolicyID, PolicyVersion: 1, AuditRetentionVersion: 1}
	executor, err := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: execution, Sessions: reader, MFAPasskey: &selection})
	if err != nil {
		t.Fatal("passkey MFA revoke construction", err)
	}
	s, _ := admitted.Session.Bindings()
	prepare := func() session.RevokeOneRequest {
		t.Helper()
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.TenantID, b.UserID, b.ActorID = s.TenantID, s.UserID, identity.ActorID(s.UserID)
		b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, s.SessionID
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		command, err := session.NewRevokeOneCommand(b, admitted.Session)
		if err != nil {
			t.Fatal(err)
		}
		request, err := reader.PrepareRevokeOne(admitted, command)
		if err != nil {
			t.Fatal(err)
		}
		return request
	}
	for _, mode := range []string{"mapping", "factor", "credential"} {
		request := prepare()
		var restore string
		switch mode {
		case "mapping":
			selected.authority.(*mfaPasskeyMappingComponent).version++
		case "factor":
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
				t.Fatal(err)
			}
			restore = `UPDATE identity_mfa.factor_authorities SET version=version-1 WHERE tenant_id=$1 AND user_id=$2`
		case "credential":
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(s.TenantID), string(s.UserID), s.Authentication.CredentialID); err != nil {
				t.Fatal(err)
			}
			restore = `UPDATE identity.credential_references SET enabled=true WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`
		}
		result, executionErr := executor.ExecuteRevokeOne(ctx, request)
		if mode == "mapping" {
			selected.authority.(*mfaPasskeyMappingComponent).version--
		} else {
			args := []any{string(s.TenantID), string(s.UserID)}
			if mode == "credential" {
				args = append(args, s.Authentication.CredentialID)
			}
			if _, err := pool.Raw().Exec(ctx, restore, args...); err != nil {
				t.Fatal(err)
			}
		}
		if executionErr == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("withdrawn MFA authority authorized revocation", mode)
		}
		command, _ := request.Command()
		original, _ := command.RevokeOne()
		var claims int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, original.Binding.CommandID)).Scan(&claims); err != nil || claims != 1 {
			t.Fatal("denial never reached native current-owner transaction", mode, executionErr, err)
		}
		if current, err := reader.Get(ctx, input); err != nil || !current.Authenticated {
			t.Fatal("denied revocation changed original session", mode, err)
		}
	}
	if result, err := executor.ExecuteRevokeOne(ctx, prepare()); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("current passkey/TOTP session cannot revoke itself", err)
	}
	if result, err := reader.Get(ctx, input); err != nil || result.Authenticated {
		t.Fatal("revoked passkey/TOTP session still authenticates", err)
	}
}

func (a *mfaPasskeyMappingComponent) ObserveMFAPasskeySession(ctx context.Context, namespace string, _ session.Session) (MFAPasskeySessionAuthorityObservation, error) {
	if ctx.Err() != nil || namespace != "rp-a" {
		return MFAPasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	return MFAPasskeySessionAuthorityObservation{PasskeyVersion: a.version, ReadStartedAt: a.now, ValidUntil: a.now.Add(20 * time.Second)}, nil
}

func (a *mfaPasskeyMappingComponent) RequireMFAPasskeySession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, namespace string, record session.Session) error {
	if _, _, _, err := w.FeatureScope(owner); err != nil {
		return err
	}
	s, err := record.Bindings()
	if err != nil || ctx.Err() != nil || namespace != "rp-a" {
		return identity.ForbiddenError{}
	}
	v, err := s.Authority.Bindings()
	if err != nil || !v.Passkey.Present || v.Passkey.Binding.Version != a.version {
		return identity.ForbiddenError{}
	}
	return nil
}

func testPasskeyMFASessionRead(t *testing.T, ctx context.Context, pool *database.Pool, config Config, profile MagicLinkAdmissionConfig, validation session.ServiceConfig, original session.Session, request session.GetRequest) {
	t.Helper()
	// The enclosing component installed the selected session histories. The
	// separate populated-record oracle proves the forward migration itself.
	wire, _, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := original.Bindings()
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3 WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID, wire); err != nil {
			t.Error("original session restoration failed", err)
		}
	}()
	m, _ := original.MFAAuthentication().Bindings()
	primary, _ := original.MagicLinkAuthentication().Bindings()
	const credentialID = "passkey-mfa-reader-fixture"
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',1,true)`, string(s.TenantID), string(s.UserID), credentialID); err != nil {
		t.Fatal(err)
	}
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 1, CredentialID: credentialID, CredentialVersion: 1, Proof: auth.Proof{ID: auth.ProofID(m.PrimaryCommandID), Tenant: string(s.TenantID), Subject: string(s.UserID), Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: session.PasskeyMFAPrimaryPurpose, Audience: s.Audience, IssuedAt: primary.AuthenticatedAt, ExpiresAt: primary.ValidUntil}}
	v, _ := s.Authority.Bindings()
	v.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:rp-a:reader", Version: 4}}
	s.Authority, err = session.NewAuthoritySnapshot(v)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithPasskeyMFA(s, original.MFAAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3 WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID, payload); err != nil {
		t.Fatal("complete passkey/TOTP record denied", err)
	}
	p := PasskeyAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, RPNamespace: "rp-a"}
	mapping := &mfaPasskeyMappingComponent{version: 4, now: validation.Clock.Now()}
	service, err := NewMFAPasskeySessionService(pool, MFAPasskeySessionServiceConfig{Repository: config, Profile: p, Validation: validation, Authority: mapping})
	if err != nil {
		t.Fatal(err)
	}
	ordinary := PasskeySessionAdmission{Profile: p, Authority: &passkeyTestAuthority{}}
	selected := MFAPasskeySessionAdmission{Profile: p, Authority: mapping}
	combined, err := NewSelectedSessionService(pool, SelectedSessionServiceConfig{Repository: config, Validation: validation, Admission: SelectedSessionAdmissionConfig{Passkey: &ordinary, MFAPasskey: &selected}})
	if err != nil {
		t.Fatal(err)
	}
	readers := []*session.SessionService{service, combined}
	for _, reader := range readers {
		got, err := reader.Get(ctx, request)
		factor, factorErr := got.Session.MFAAuthentication().Bindings()
		if err != nil || !got.Authenticated || factorErr != nil || factor != m || !got.ValidUntil().Equal(validation.Clock.Now().Add(20*time.Second-validation.ClockUncertainty)) {
			t.Fatal("current passkey and real confirmed TOTP cannot read original session", err, factorErr)
		}
	}
	for _, mode := range []string{"mapping", "factor", "enrollment", "credential"} {
		var restore string
		switch mode {
		case "mapping":
			mapping.version++
		case "factor":
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
				t.Fatal(err)
			}
			restore = `UPDATE identity_mfa.factor_authorities SET version=version-1 WHERE tenant_id=$1 AND user_id=$2`
		case "enrollment":
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=enrollment_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
				t.Fatal(err)
			}
			restore = `UPDATE identity_mfa.totp_factors SET enrollment_version=enrollment_version-1 WHERE tenant_id=$1 AND user_id=$2`
		case "credential":
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id='passkey-mfa-reader-fixture'`, string(s.TenantID), string(s.UserID)); err != nil {
				t.Fatal(err)
			}
			restore = `UPDATE identity.credential_references SET enabled=true WHERE tenant_id=$1 AND user_id=$2 AND credential_id='passkey-mfa-reader-fixture'`
		}
		for _, reader := range readers {
			if got, err := reader.Get(ctx, request); err != nil || got.Authenticated {
				t.Fatal("changed owner retained or downgraded authentication", mode, err)
			}
		}
		if restore != "" {
			if _, err := pool.Raw().Exec(ctx, restore, string(s.TenantID), string(s.UserID)); err != nil {
				t.Fatal(err)
			}
		} else {
			mapping.version--
		}
	}
}
