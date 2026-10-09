//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This seam owns synthetic verifier state only. It proves the kernel effect's
// real shared transaction, not password/proof policy or production outbox wiring.
type replacementNativePhase struct{ fail, wrongReceipt bool }

func (*replacementNativePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*replacementNativePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (*replacementNativePhase) CredentialReplacement(c identity.Command) (CredentialReplacementIntent, error) {
	s, ok := c.Feature()
	if !ok {
		return CredentialReplacementIntent{}, invalidCredentialReplacement()
	}
	return decodeCredentialReplacement(s)
}
func (p *replacementNativePhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != p.FeatureOperations()[0] || len(s.Fields) != 8 || len(plan.Audits) != 1 || plan.Audits[0].EventType != "identity.password.change" {
		return invalidPlan()
	}
	return nil
}
func (p *replacementNativePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	s, _ := c.Feature()
	intent, err := p.CredentialReplacement(c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	n, err := w.Exec(ctx, `UPDATE public.identity_test_replacement_native SET version=version+1,command_id=$4 WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND version=$5::numeric`, string(s.Binding.TenantID), string(s.Binding.UserID), s.Binding.RecordID, string(s.Binding.CommandID), strconv.FormatUint(intent.Credential.Version, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 || p.fail {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	r := identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: intent.Credential.Version, AfterVersion: intent.Credential.Version + 1}
	if p.wrongReceipt {
		r.AfterVersion++
	}
	return r, nil
}
func (*replacementNativePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_replacement_native")
}

type replacementOutboxPhase struct{ recoveryLifecyclePhase }

func (p *replacementOutboxPhase) PersistCredentialReplacement(ctx context.Context, w Work) error {
	r, err := w.StagedCredentialReplacement()
	if err != nil {
		return err
	}
	if err := p.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO public.identity_test_replacement_epochs(command_id,user_before,user_after,epoch_before,epoch_after,record_before,record_after) VALUES($1,$2::numeric,$3::numeric,$4::numeric,$5::numeric,$6::numeric,$7::numeric)`, string(w.state.binding.CommandID), strconv.FormatUint(r.BeforeUserVersion, 10), strconv.FormatUint(r.AfterUserVersion, 10), strconv.FormatUint(r.BeforeAuthorityVersion, 10), strconv.FormatUint(r.AfterAuthorityVersion, 10), strconv.FormatUint(r.BeforeCredentialVersion, 10), strconv.FormatUint(r.Credential.Version, 10))
	return err
}

func testCredentialReplacement(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_replacement_native(tenant_id text,user_id text,credential_id text,version numeric NOT NULL,command_id text UNIQUE,PRIMARY KEY(tenant_id,user_id,credential_id)); CREATE TABLE public.identity_test_replacement_epochs(command_id text PRIMARY KEY,user_before numeric,user_after numeric,epoch_before numeric,epoch_after numeric,record_before numeric,record_after numeric)`); err != nil {
		t.Fatal(err)
	}
	native, auditing, outbox := &replacementNativePhase{}, &recoveryAuditPhase{}, &replacementOutboxPhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditing, outbox, native})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"commit", "native-failure", "receipt-failure", "audit-failure", "outbox-failure", "stale-user", "stale-epoch", "stale-record", "banned", "deleted", "suspended", "anonymized", "disabled", "expired", "full-width", "recovery-negative", "recovery-retained", "recovery-missing"} {
		t.Run(scenario, func(t *testing.T) {
			native.fail, native.wrongReceipt = scenario == "native-failure", scenario == "receipt-failure"
			auditing.fail, outbox.fail = scenario == "audit-failure", scenario == "outbox-failure"
			b := codecBinding()
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			id, e := identity.NewSubjectID()
			if e != nil {
				t.Fatal(e)
			}
			b.UserID, b.RecordID = identity.UserID(id), "replaced"
			op := native.FeatureOperations()[0]
			b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
			intent := CredentialReplacementIntent{Credential: identity.CredentialRef{ID: identity.CredentialID(b.RecordID), TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialPassword, Owner: op.Owner, Version: 7}, ExpectedUserVersion: 11, ExpectedAuthorityVersion: 13}
			if scenario == "full-width" {
				intent.ExpectedAuthorityVersion = ^uint64(0) - 1
			}
			uv, av, cv := intent.ExpectedUserVersion, intent.ExpectedAuthorityVersion, intent.Credential.Version
			status, enabled := "active", true
			var expiry *time.Time
			switch scenario {
			case "banned", "deleted", "suspended", "anonymized":
				status = scenario
			case "disabled":
				enabled = false
			case "expired":
				past := time.Now().UTC().Add(-time.Hour)
				expiry = &past
			case "stale-user":
				uv++
			case "stale-epoch":
				av++
			case "stale-record":
				cv++
			}
			if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,credential_version,identifier_version,authority_version) VALUES($1,$2,$3,$4::numeric,$5::numeric,17,19)`, string(b.TenantID), string(b.UserID), status, strconv.FormatUint(uv, 10), strconv.FormatUint(av, 10)); e != nil {
				t.Fatal(e)
			}
			if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled,expires_at) VALUES($1,$2,$3,1,'identity/password',$4::numeric,$5,$6)`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(cv, 10), enabled, expiry); e != nil {
				t.Fatal(e)
			}
			if _, e := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_replacement_native VALUES($1,$2,$3,$4::numeric,NULL)`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(cv, 10)); e != nil {
				t.Fatal(e)
			}
			fields, e := CredentialReplacementFields(intent)
			if e != nil {
				t.Fatal(e)
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.SubjectType, plan.Feature = registry.Descriptors(), "credential", &FeatureRegistration{Contributor: native.Descriptor(), Operation: op}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "identity.password.change", "protected"
			plan.Lifecycle = &LifecyclePlan{EventType: "password.changed.v1", BeforeVersion: intent.Credential.Version, AfterVersion: intent.Credential.Version + 1}
			seed, e := securityMutationAudit(ctx, b, 7, 8, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, "credential", b.RecordID, "protected", true)
			if e != nil {
				t.Fatal(e)
			}
			plan.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(b, op, "credential", seed)
			if e != nil {
				t.Fatal(e)
			}
			plan, e = c.PrepareCommandPlan(b, command, plan)
			if e != nil {
				t.Fatal("prepare", e)
			}
			r, _, e := c.ReserveCommand(ctx, b, command, plan)
			if e != nil {
				t.Fatal("reserve", e)
			}
			if scenario == "recovery-negative" || scenario == "recovery-retained" || scenario == "recovery-missing" {
				key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
					t.Fatal(e)
				}
				if scenario == "recovery-retained" {
					if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_replacements VALUES($1,$2,$3,$4,$5,$6,11,12,13,14,7,8)`, string(b.CommandID), key, string(b.TenantID), string(b.UserID), b.RecordID, b.OperationID); e != nil {
						t.Fatal(e)
					}
				}
				if scenario == "recovery-missing" {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE identity.credential_replacements RENAME TO credential_replacements_hidden`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
						defer stop()
						if _, e := pool.Raw().Exec(cleanup, `ALTER TABLE identity.credential_replacements_hidden RENAME TO credential_replacements`); e != nil {
							t.Error("replacement fixture restoration", e)
						}
					}()
				}
				q, caller := queryInputs(b)
				observed, e := c.RecoverCommand(ctx, q, caller)
				var unavailable identity.UnavailableError
				want := identity.CommitOutcomeInProgress
				if scenario == "recovery-negative" {
					want = identity.CommitOutcomeNotCommitted
				}
				if !errors.As(e, &unavailable) || observed.Outcome != want {
					t.Fatal("unsafe replacement recovery conclusion", observed.Outcome, e)
				}
				return
			}
			w, e := c.Begin(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, e := c.ApplyFeature(ctx, w, command)
			if e == nil {
				result, e = c.Commit(w, result)
			} else {
				c.Abort(w, e)
			}
			success := scenario == "commit" || scenario == "full-width"
			if success && (e != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("replacement commit", e)
			}
			if !success && e == nil {
				t.Fatal("unsafe replacement committed")
			}
			got, e := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: b.UserID, CredentialID: intent.Credential.ID})
			if e != nil {
				t.Fatal(e)
			}
			delta := uint64(0)
			if success {
				delta = 1
			}
			if got.User.Version != uv+delta || got.AuthorityVersion != av+delta || got.Credential.Version != cv+delta || got.Enabled != enabled || got.User.Status != identity.Status(status) {
				t.Fatal("replacement kernel dimensions not atomic")
			}
			var nv, userEpoch, identifierEpoch string
			var retained, epochs int
			if e := pool.Raw().QueryRow(ctx, `SELECT n.version::text,u.authority_version::text,u.identifier_version::text,(SELECT count(*) FROM identity.credential_replacements WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_replacement_epochs WHERE command_id=$3) FROM public.identity_test_replacement_native n JOIN identity.users u USING(tenant_id,user_id) WHERE n.tenant_id=$1 AND n.user_id=$2`, string(b.TenantID), string(b.UserID), string(b.CommandID)).Scan(&nv, &userEpoch, &identifierEpoch, &retained, &epochs); e != nil || nv != strconv.FormatUint(cv+delta, 10) || userEpoch != "19" || identifierEpoch != "17" || retained != int(delta) || epochs != int(delta) {
				t.Fatal("replacement native/evidence atomicity", e)
			}
			if success {
				var ub, ua, eb, ea, rb, ra string
				if e := pool.Raw().QueryRow(ctx, `SELECT user_before::text,user_after::text,epoch_before::text,epoch_after::text,record_before::text,record_after::text FROM public.identity_test_replacement_epochs WHERE command_id=$1`, string(b.CommandID)).Scan(&ub, &ua, &eb, &ea, &rb, &ra); e != nil || ub != strconv.FormatUint(uv, 10) || ua != strconv.FormatUint(uv+1, 10) || eb != strconv.FormatUint(av, 10) || ea != strconv.FormatUint(av+1, 10) || rb != strconv.FormatUint(cv, 10) || ra != strconv.FormatUint(cv+1, 10) {
					t.Fatal("replacement outbox relabeled independent versions", e)
				}
				_, replay, e := c.ReserveCommand(ctx, b, command, plan)
				if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || *replay.Feature != *result.Feature {
					t.Fatal("replacement original receipt replay", e)
				}
			}
		})
	}
}
