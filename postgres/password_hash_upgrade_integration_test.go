//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

// Native material/proof and lifecycle SQL seams deliberately isolate kernel
// ownership and atomicity. They are not a password verifier, session adapter or
// production outbox interoperability proof; the owning composition follows.
type passwordUpgradePhase struct {
	expected                            identity.Command
	recipient                           RecipientRecord
	fail, skipApply, duplicate, foreign bool
	finalExpiry                         bool
	ignoredCursor                       bool
	substituteSuccessor                 bool
}

func (*passwordUpgradePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *passwordUpgradePhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.expected.PasswordSigninFeature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *passwordUpgradePhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	s, ok := c.PasswordSigninFeature()
	if !ok || c != p.expected || plan.SubjectType != "session" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "session.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 {
		return invalidPlan()
	}
	_, err := decodePasswordHashUpgrade(s)
	return err
}
func (p *passwordUpgradePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.ignoredCursor {
		rows, err := w.Query(ctx, `SELECT 1`)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		_ = w.PreparePasswordHashUpgrade(ctx, p, c, p.recipient)
		rows.Close()
		s, _ := c.PasswordSigninFeature()
		i, _ := decodePasswordHashUpgrade(s)
		_, err = w.Exec(ctx, `UPDATE public.identity_test_upgrade_material SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(i.Admission.Credential.TenantID), string(i.Admission.Credential.UserID))
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	if p.foreign {
		// Same metadata with distinct custody must not replace the invocation.
		s, _ := c.PasswordSigninFeature()
		secret, cookie, _ := c.PasswordSigninCustody()
		other, _ := identity.NewFeaturePasswordSigninCommand(s, secret, cookie)
		_ = w.PreparePasswordHashUpgrade(ctx, p, other, p.recipient)
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	if err := w.PreparePasswordHashUpgrade(ctx, p, c, p.recipient); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.PasswordSigninFeature()
	i, _ := decodePasswordHashUpgrade(s)
	n, err := w.Exec(ctx, `UPDATE public.identity_test_upgrade_material SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric`, string(i.Admission.Credential.TenantID), string(i.Admission.Credential.UserID), strconv.FormatUint(i.Admission.Credential.Version, 10))
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.skipApply {
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	receipt, err := w.ApplyPasswordHashUpgrade(ctx, p, c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.duplicate {
		_, _ = w.ApplyPasswordHashUpgrade(ctx, p, c)
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	if p.substituteSuccessor {
		secret, cookie, _ := c.PasswordSigninCustody()
		other, _ := identity.NewFeaturePasswordSigninCommand(s, secret, cookie)
		// Even a caller ignoring the denial must not commit prior material and
		// kernel successor writes under the original command's fingerprint.
		_ = w.RequireFeatureCommand(ctx, p, other)
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	recipient, admission, err := w.PasswordHashUpgradeSuccessor(p)
	if err != nil || recipient.User.Version != i.ExpectedUserVersion+1 || recipient.CredentialAuthorityVersion != i.Admission.CredentialAuthorityVersion+1 || recipient.UserAuthorityVersion != i.Admission.UserAuthorityVersion || recipient.IdentifierAuthorityVersion != i.Admission.IdentifierAuthorityVersion || recipient.ObservedAt != p.recipient.ObservedAt || admission.Credential != receipt.Credential || admission.CredentialAuthorityVersion != receipt.AfterAuthorityVersion {
		return identity.FeatureReceipt{}, invalidWork()
	}
	if _, err := w.RequireRecipientCredential(ctx, p, recipient, admission); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_upgrade_effects VALUES($1,$2,$3::numeric)`, string(s.Binding.CommandID), string(recipient.User.ID), strconv.FormatUint(receipt.Credential.Version, 10)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.finalExpiry {
		// Establish an exact primary-clock boundary; the final read below waits
		// across it, rather than relying on test-runner scheduling.
		if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '100 milliseconds' WHERE tenant_id=$1 AND user_id=$2`, string(i.Admission.Credential.TenantID), string(i.Admission.Credential.UserID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (p *passwordUpgradePhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if c != p.expected {
		return invalidWork()
	}
	if !p.finalExpiry {
		return nil
	}
	s, _ := c.PasswordSigninFeature()
	i, _ := decodePasswordHashUpgrade(s)
	rows, err := w.Query(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(epoch FROM(expires_at-clock_timestamp())))+0.01) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2`, string(i.Admission.Credential.TenantID), string(i.Admission.Credential.UserID))
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	err = rows.Err()
	rows.Close()
	return err
}
func (*passwordUpgradePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_upgrade_effects")
}

type passwordUpgradeOutbox struct {
	recoveryLifecyclePhase
	noUpgrade bool
}

func (p *passwordUpgradeOutbox) PersistLifecycle(ctx context.Context, w Work) error {
	if p.noUpgrade {
		return p.recoveryLifecyclePhase.PersistLifecycle(ctx, w)
	}
	r, err := w.StagedPasswordHashUpgrade()
	if err != nil {
		return err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_upgrade_epochs VALUES($1,$2::numeric,$3::numeric,$4::numeric,$5::numeric,$6::numeric,$7::numeric)`, string(r.CommandID), strconv.FormatUint(r.BeforeUserVersion, 10), strconv.FormatUint(r.AfterUserVersion, 10), strconv.FormatUint(r.BeforeAuthorityVersion, 10), strconv.FormatUint(r.AfterAuthorityVersion, 10), strconv.FormatUint(r.BeforeCredentialVersion, 10), strconv.FormatUint(r.Credential.Version, 10)); err != nil {
		return err
	}
	return p.recoveryLifecyclePhase.PersistLifecycle(ctx, w)
}

func testPasswordHashUpgrade(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_upgrade_material(tenant_id text,user_id text,version numeric,PRIMARY KEY(tenant_id,user_id)); CREATE TABLE public.identity_test_upgrade_effects(command_id text PRIMARY KEY,user_id text,version numeric); CREATE TABLE public.identity_test_upgrade_epochs(command_id text PRIMARY KEY,user_before numeric,user_after numeric,epoch_before numeric,epoch_after numeric,credential_before numeric,credential_after numeric)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "native-failure", "audit-failure", "outbox-failure", "unapplied", "duplicate", "foreign-command", "substituted-successor", "stale-user", "stale-credential", "stale-authority", "disabled", "suspended", "expired", "final-expiry", "ignored-cursor", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			user, _ := identity.NewSubjectID()
			tenant := identity.TenantID("hash-upgrade")
			for _, statement := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,'active',11,19,17,13)`, []any{string(tenant), string(user)}},
				{`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'credential',1,'identity/password',7,true)`, []any{string(tenant), string(user)}},
				{`INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,$2,'email',$3,true,true,1,2,1,clock_timestamp())`, []any{string(tenant), string(user), string(user) + "@example.test"}},
				{`INSERT INTO public.identity_test_upgrade_material VALUES($1,$2,7)`, []any{string(tenant), string(user)}},
			} {
				if _, err := pool.Raw().Exec(ctx, statement.sql, statement.args...); err != nil {
					t.Fatal(err)
				}
			}
			recipient, err := repo.ResolveRecipient(ctx, RecipientQuery{TenantID: tenant, Kind: identity.IdentifierEmail, CanonicalValue: string(user) + "@example.test", Eligibility: RecipientVerified})
			if err != nil || recipient.Suppressed {
				t.Fatal("original recipient", err)
			}
			intent := passwordUpgradeIntentFixture()
			intent.Admission.Credential.TenantID, intent.Admission.Credential.UserID = tenant, identity.UserID(user)
			if mode == "stale-user" || mode == "stale-authority" || mode == "suspended" {
				sql := `UPDATE identity.users SET version=12 WHERE tenant_id=$1 AND user_id=$2`
				if mode == "stale-authority" {
					sql = `UPDATE identity.users SET credential_version=14 WHERE tenant_id=$1 AND user_id=$2`
				}
				if mode == "suspended" {
					sql = `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`
				}
				if _, err := pool.Raw().Exec(ctx, sql, string(tenant), string(user)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "stale-credential" || mode == "disabled" || mode == "expired" {
				sql := `UPDATE identity.credential_references SET version=8 WHERE tenant_id=$1 AND user_id=$2`
				if mode == "disabled" {
					sql = `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2`
				}
				if mode == "expired" {
					sql = `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2`
				}
				if _, err := pool.Raw().Exec(ctx, sql, string(tenant), string(user)); err != nil {
					t.Fatal(err)
				}
			}
			prepare := func() (*Coordinator, identity.Command, CommandPlan, *passwordUpgradePhase) {
				s := passwordUpgradeSpecFixture(t, intent)
				s.Binding.CommandID, _ = identity.NewCommandID()
				s.Binding.AnonymousFlowID = string(s.Binding.CommandID)
				secret, err := primitive.NewSecret([]byte("synthetic-original-password"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(secret.Destroy)
				command, err := identity.NewFeaturePasswordSigninCommand(s, secret, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
				if err != nil {
					t.Fatal(err)
				}
				p := &passwordUpgradePhase{expected: command, recipient: recipient, fail: mode == "native-failure", skipApply: mode == "unapplied", duplicate: mode == "duplicate", foreign: mode == "foreign-command", finalExpiry: mode == "final-expiry", ignoredCursor: mode == "ignored-cursor"}
				p.substituteSuccessor = mode == "substituted-successor"
				audits, outbox := &recoveryAuditPhase{}, &passwordUpgradeOutbox{}
				outbox.noUpgrade = p.ignoredCursor
				audits.fail, outbox.fail = mode == "audit-failure", mode == "outbox-failure"
				registry, err := NewContributorRegistry([]Contributor{repo, audits, outbox, p})
				if err != nil {
					t.Fatal(err)
				}
				c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
				if err != nil {
					t.Fatal(err)
				}
				_, _, plan := featurePlanFixture(t)
				plan.Contributors, plan.SubjectType, plan.Feature = registry.Descriptors(), "session", &FeatureRegistration{Contributor: p.Descriptor(), Operation: s.Operation}
				plan.Lifecycle = &LifecyclePlan{EventType: "session.created.v1"}
				plan.Audits[0].EventType, plan.Audits[0].RetentionClass = s.Operation.OperationID, "protected"
				seed, err := securityMutationAudit(ctx, s.Binding, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", s.Operation.OperationID, "session", s.Binding.AnonymousFlowID, "protected", true)
				if err != nil {
					t.Fatal(err)
				}
				plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
				if err != nil {
					t.Fatal(err)
				}
				plan, err = c.PrepareCommandPlan(s.Binding, command, plan)
				if err != nil {
					t.Fatal(err)
				}
				return c, command, plan, p
			}
			c, command, plan, phase := prepare()
			execute := func(c *Coordinator, command identity.Command, plan CommandPlan) (identity.CommandResult, error) {
				s, _ := command.PasswordSigninFeature()
				r, _, err := c.ReserveCommand(ctx, s.Binding, command, plan)
				if err != nil {
					return identity.CommandResult{}, err
				}
				w, err := c.Begin(ctx, r)
				if err != nil {
					return identity.CommandResult{}, err
				}
				result, err := c.ApplyFeature(ctx, w, command)
				if err == nil {
					result, err = c.Commit(w, result)
				} else {
					c.Abort(w, err)
				}
				return result, err
			}
			committed := 0
			if mode == "concurrent" {
				other, otherCommand, otherPlan, _ := prepare()
				done := make(chan bool, 2)
				start := make(chan struct{})
				for _, attempt := range []struct {
					c       *Coordinator
					command identity.Command
					plan    CommandPlan
				}{{c, command, plan}, {other, otherCommand, otherPlan}} {
					go func() {
						<-start
						result, err := execute(attempt.c, attempt.command, attempt.plan)
						done <- err == nil && result.Outcome == identity.CommitOutcomeCommitted
					}()
				}
				close(start)
				for range 2 {
					if <-done {
						committed++
					}
				}
				if committed != 1 {
					t.Fatal("competing upgrades lack one CAS winner")
				}
			} else {
				result, err := execute(c, command, plan)
				if mode == "commit" {
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("upgrade commit", err)
					}
					committed = 1
				} else if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("unsafe upgrade committed")
				}
			}
			if _, _, err := (Work{}).PasswordHashUpgradeSuccessor(phase); err == nil {
				t.Fatal("post-work successor authority")
			}
			var uv, av, cv, mv, ue, ie string
			if err := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,c.version::text,m.version::text,u.authority_version::text,u.identifier_version::text FROM identity.users u JOIN identity.credential_references c USING(tenant_id,user_id) JOIN public.identity_test_upgrade_material m USING(tenant_id,user_id) WHERE u.tenant_id=$1 AND u.user_id=$2`, string(tenant), string(user)).Scan(&uv, &av, &cv, &mv, &ue, &ie); err != nil {
				t.Fatal(err)
			}
			wantUser, wantAuthority, wantCredential := 11+committed, 13+committed, 7+committed
			if mode == "stale-user" {
				wantUser++
			}
			if mode == "stale-authority" {
				wantAuthority++
			}
			if mode == "stale-credential" {
				wantCredential++
			}
			if uv != strconv.Itoa(wantUser) || av != strconv.Itoa(wantAuthority) || cv != strconv.Itoa(wantCredential) || mv != strconv.Itoa(7+committed) || ue != "19" || ie != "17" {
				t.Fatal("material/kernel dimensions not atomic")
			}
			var effects, epochs int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_upgrade_effects WHERE user_id=$1),(SELECT count(*) FROM public.identity_test_upgrade_epochs e JOIN public.identity_test_upgrade_effects f USING(command_id) WHERE f.user_id=$1)`, string(user)).Scan(&effects, &epochs); err != nil || effects != committed || epochs != committed {
				t.Fatal("retained effects/lifecycle not atomic", err)
			}
		})
	}
}
