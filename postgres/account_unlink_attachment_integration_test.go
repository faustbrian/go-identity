//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// This participant requires the genuine staged grant's issued effect to exist
// before reservation. It is a SQL ordering/atomicity double, not the capability
// library's durable participant or complete password-authorized unlink owner.
type unlinkAttachmentCapability struct {
	capabilityExecutionProbe
	fail, failFinalize bool
}

type unlinkAttachmentAudit struct{ accountLinkSQLAudit }

func (*unlinkAttachmentAudit) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	plans, err := w.AuditPlans()
	if err != nil || len(plans) != 2 {
		return RecoveryUnknown, invalidAudit()
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_audits")
}

func (p *unlinkAttachmentCapability) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `INSERT INTO public.unlink_prepared_capability(command_id,capability_id,generation)
SELECT $1,$2,$3::numeric WHERE EXISTS(SELECT 1 FROM public.identity_test_issuance WHERE command_id=$1 AND capability_id=$2 AND proof_fingerprint=$4 AND replay_digest=$5)`, string(b.Command.CommandID), b.Plan.CapabilityID, b.Generation, b.Plan.ProofFingerprint[:], b.Plan.ReplayDigest[:])
	if err != nil {
		return err
	}
	if n != 1 || p.fail {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *unlinkAttachmentCapability) RebindCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.unlink_prepared_capability SET generation=$3::numeric WHERE command_id=$1 AND capability_id=$2 AND generation=$4::numeric`, string(b.Command.CommandID), b.Plan.CapabilityID, b.Generation, b.PreviousGeneration)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *unlinkAttachmentCapability) ApplyCapability(ctx context.Context, w CapabilityApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.unlink_prepared_capability SET state='applied' WHERE command_id=$1 AND capability_id=$2 AND generation=$3::numeric AND state='reserved'`, string(b.Command.CommandID), b.Plan.CapabilityID, b.Generation)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *unlinkAttachmentCapability) FinalizeCapability(ctx context.Context, w CapabilityFinalizeWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if p.failFinalize {
		return identity.UnavailableError{}
	}
	n, err := w.Exec(ctx, `UPDATE public.unlink_prepared_capability SET state='finalized' WHERE command_id=$1 AND capability_id=$2 AND generation=$3::numeric AND state='applied'`, string(b.Command.CommandID), b.Plan.CapabilityID, b.Generation)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *unlinkAttachmentCapability) ReleaseCapability(ctx context.Context, w CapabilityReleaseWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.unlink_prepared_capability SET state='released',generation=$3::numeric WHERE command_id=$1 AND capability_id=$2 AND generation=$4::numeric AND state='reserved'`, string(b.Command.CommandID), b.Plan.CapabilityID, b.Generation, b.PreviousGeneration)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *unlinkAttachmentCapability) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.CapabilityBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT state,generation::text FROM public.unlink_prepared_capability WHERE command_id=$1 AND capability_id=$2`, string(b.Command.CommandID), b.Plan.CapabilityID)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var state, generation string
	if !rows.Next() || rows.Scan(&state, &generation) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if state == "reserved" && generation == strconv.FormatUint(b.PreviousGeneration, 10) {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}

// These phase doubles exercise the actual kernel transaction. Their controlled
// password eligibility/effect marker do not replace the genuine password,
// provider vault or session owners in the eventual native consumer proof.
type unlinkAttachmentProvider struct {
	preparedUnlinkOwnerProbe
	stage, fault string
	generated    identity.Command
	declaration  CommandPlan
	issuance     CapabilityIssuancePlan
}

func (p *unlinkAttachmentProvider) GenerateAccountUnlinkPreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return []byte("synthetic-authenticated-original-issuer-checkpoint"), nil
}

func (p *unlinkAttachmentProvider) RestoreAccountUnlinkPreparation(_ context.Context, _ identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	if generation == 0 || !bytes.Equal(wire, []byte("synthetic-authenticated-original-issuer-checkpoint")) {
		return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, invalidPreparation()
	}
	return p.generated, p.declaration, p.issuance, nil
}

func (p *unlinkAttachmentProvider) CheckAccountUnlink(ctx context.Context, w AccountUnlinkWork) error {
	spec, final, err := w.Command(p)
	p.stage = "initial-check"
	if final {
		p.stage = "final-check"
		if p.fault == "final-check-denied" {
			return identity.ForbiddenError{}
		}
	}
	if err != nil {
		return err
	}
	userVersion, credentialVersion := spec.Change.ExpectedUserVersion, spec.Change.ExpectedCredentialVersion
	if final {
		userVersion++
		credentialVersion++
	}
	ownedVersion, err := w.CredentialAuthorityVersion(p)
	if err != nil || ownedVersion != credentialVersion {
		p.stage += ": credential authority did not follow exact Work"
		return identity.ForbiddenError{}
	}
	originalFactorVersion, err := w.OriginalFactorAuthorityVersion(p)
	if err != nil || originalFactorVersion != 7 {
		p.stage += ": original factor generation unavailable"
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text,credential_version::text,status FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(spec.Binding.TenantID), string(spec.Binding.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var user, credential, status string
	if !rows.Next() || rows.Scan(&user, &credential, &status) != nil || rows.Next() || rows.Err() != nil {
		p.stage += ": invalid authority row"
		return identity.ForbiddenError{}
	}
	if user != strconv.FormatUint(userVersion, 10) || credential != strconv.FormatUint(credentialVersion, 10) || status != "active" {
		p.stage += ": authority versions/status " + user + "/" + credential + "/" + status
		return identity.ForbiddenError{}
	}
	p.stage += ": checked"
	return nil
}

func (p *unlinkAttachmentProvider) EligibleAccountUnlinkMethods(_ context.Context, w AccountUnlinkWork, methods []identity.LoginMethod) ([]identity.LoginMethod, error) {
	p.stage = "eligibility"
	if _, _, err := w.Command(p); err != nil {
		return nil, err
	}
	for i := range methods {
		methods[i].Usable = methods[i].Credential.ID == "password-key"
	}
	return methods, nil
}

func (p *unlinkAttachmentProvider) PersistAccountUnlink(ctx context.Context, w AccountUnlinkWork) error {
	p.stage = "persist"
	spec, err := w.PersistenceIntent(p)
	if err != nil {
		return invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.unlink_provider_effect(command_id,finalized) VALUES($1,false)`, string(spec.Binding.CommandID))
	return err
}

func (p *unlinkAttachmentProvider) FinalizeAccountUnlink(ctx context.Context, w AccountUnlinkWork) error {
	p.stage = "finalize"
	spec, final, err := w.Command(p)
	if err != nil || !final {
		return invalidWork()
	}
	if p.fault == "finalize-panic" {
		panic("synthetic unlink finalization failure")
	}
	n, err := w.Exec(ctx, `UPDATE public.unlink_provider_effect SET finalized=true WHERE command_id=$1 AND NOT finalized`, string(spec.Binding.CommandID))
	if err == nil && n != 1 {
		return identity.UnavailableError{}
	}
	return err
}

func TestAccountUnlinkAttachmentIssuesAndReservesOriginalChildAtomically(t *testing.T) {
	for _, mode := range []string{"success", "public-preparation", "issuer-error", "reserve-error", "ack-before-commit", "ack-after-commit", "final-check-denied", "finalize-panic", "capability-finalize-error", "expired-attached-recovery"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, repo := newAccountAuthorityStore(t)
			expansion := AccountUnlinkPreparationMigrationSource{Base: unlinkPreparationInstalledPrefix(), Version: 20}
			installUnlinkPreparationHistory(t, ctx, pool, AccountUnlinkPreparationValidationMigrationSource{Base: expansion, Version: 21})
			if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.unlink_preparation_charge(command_id text PRIMARY KEY);
CREATE TABLE public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL);
CREATE TABLE public.unlink_prepared_capability(command_id text PRIMARY KEY,capability_id text NOT NULL,generation numeric NOT NULL,state text NOT NULL DEFAULT 'reserved');
CREATE TABLE public.unlink_provider_effect(command_id text PRIMARY KEY,finalized boolean NOT NULL);
CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL,no_change boolean,outcome smallint,reason text);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			original := recordUnlinkPreparation(t, func(p *identity.AccountUnlinkPreparationCommand) {
				p.Primary.Proof.IssuedAt, p.Primary.Proof.ExpiresAt = now.Add(-time.Minute), now.Add(3*time.Minute)
				p.Counters.PreparedAt = now
			}, 1)
			input, _, _ := original.AccountUnlinkPreparationInput()
			bare := recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, nil)
			issued, _ := bare.UnlinkAccount()
			payload := issued.Proof.Payload()
			payload.IssuedAt, payload.NotBefore, payload.ExpiresAt = now, now, now.Add(2*time.Minute)
			issued.Proof = recordGrantAt(t, payload, "proof-key", capability.DefaultLimits(), now)
			bare, err := identity.NewAccountUnlinkCommand(issued)
			if err != nil {
				t.Fatal(err)
			}
			generated, err := identity.NewAccountUnlinkCounterCommand(bare, input.Counters)
			if err != nil {
				t.Fatal(err)
			}
			_, _, declaration, _ := unlinkPreparationFixture(t)
			phase := &unlinkAttachmentProvider{fault: mode}
			issuer, consumer := &issuanceSQLPhase{}, &unlinkAttachmentCapability{}
			consumer.failFinalize = mode == "capability-finalize-error"
			finalFailure := mode == "final-check-denied" || mode == "finalize-panic" || mode == "capability-finalize-error"
			recoverAttached := mode == "expired-attached-recovery"
			registry, err := NewContributorRegistry([]Contributor{repo, &unlinkAttachmentAudit{}, &recoveryLifecyclePhase{}, consumer, &unlinkPreparationSQLCounter{}, phase, issuer})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			seedArgs := []any{string(input.Binding.TenantID), string(input.Binding.UserID), string(input.Change.AccountID)}
			for _, seed := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1) ON CONFLICT DO NOTHING`, seedArgs[:2]},
				{`INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
VALUES($1,$2,$3,'configured-oidc','https://provider.example','synthetic-subject',sha256(convert_to(octet_length('configured-oidc')::text||':configured-oidc'||octet_length('https://provider.example')::text||':https://provider.example'||octet_length('synthetic-subject')::text||':synthetic-subject','UTF8')),1,1,true)`, seedArgs},
				{`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
VALUES($1,$2,'provider-key',3,'identity/oauth',1,true),($1,$2,'password-key',1,'identity/password',1,true)`, seedArgs[:2]},
				{`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,$2,'provider-key',$3)`, seedArgs},
			} {
				if _, err := pool.Raw().Exec(ctx, seed.query, seed.args...); err != nil {
					t.Fatal(err)
				}
			}
			var prepared *PreparedAccountUnlink
			execute := func(reservation Reservation) {
				t.Helper()
				var result identity.CommandResult
				var err error
				if prepared == nil {
					result, err = c.executeAccountUnlinkReservation(ctx, repo, reservation, generated)
				} else {
					spec, ok := prepared.Intent()
					if !ok || prepared.VerifyPreparedAccountUnlink(ctx, spec) != nil {
						t.Fatal("public prepared handoff lost its exact authenticated intent")
					}
					bare, buildErr := identity.NewAccountUnlinkCommand(spec)
					if buildErr != nil {
						t.Fatal(buildErr)
					}
					result, err = prepared.Execute(ctx, bare)
				}
				if finalFailure {
					if result.Outcome != identity.CommitOutcomeNotCommitted || result.Unlink != nil {
						t.Fatal("failed finalization acknowledged unlink", result.Outcome, err, phase.stage)
					}
					state, err := repo.GetAccountUnlinkState(ctx, identity.AccountUnlinkQuery{TenantID: input.Binding.TenantID, UserID: input.Binding.UserID, AccountID: input.Change.AccountID})
					if err != nil || state.Access.User.Version != 1 || state.SocialLinkVersion != 1 || state.CredentialVersion != 1 || len(state.Access.Accounts) != 1 || len(state.Access.Methods) != 2 {
						t.Fatal("failed finalization leaked account or credential mutation", err)
					}
					var audits, noChanges, lifecycle, effects int
					if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM public.identity_test_audits WHERE no_change),(SELECT count(*) FROM public.identity_test_lifecycle),(SELECT count(*) FROM public.unlink_provider_effect)`).Scan(&audits, &noChanges, &lifecycle, &effects); err != nil || audits != 2 || noChanges != 2 || lifecycle != 0 || effects != 0 {
						t.Fatal("failed finalization leaked effects or omitted bound failure audits", err, audits, noChanges, lifecycle, effects)
					}
					var childState string
					if err := pool.Raw().QueryRow(ctx, `SELECT state FROM public.unlink_prepared_capability`).Scan(&childState); err != nil || childState != "released" {
						t.Fatal("failed finalization consumed or failed to release the original child", err)
					}
					return
				}
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Unlink == nil || result.Unlink.TombstoneVersion != 2 || result.User.Version != 2 {
					t.Fatal("protected unlink transaction did not commit its exact result", result.Outcome, err, "last provider phase:", phase.stage)
				}
				var audits, lifecycle, finalized int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM public.identity_test_lifecycle),(SELECT count(*) FROM public.unlink_provider_effect WHERE finalized)`).Scan(&audits, &lifecycle, &finalized); err != nil || audits != 2 || lifecycle != 1 || finalized != 1 {
					t.Fatal("unlink committed without both audits, lifecycle or provider finalization", err)
				}
				var proofState string
				if err := pool.Raw().QueryRow(ctx, `SELECT state FROM public.unlink_prepared_capability`).Scan(&proofState); err != nil || proofState != "finalized" {
					t.Fatal("unlink did not finalize the same one-use child", err)
				}
				state, err := repo.GetAccountUnlinkState(ctx, identity.AccountUnlinkQuery{TenantID: input.Binding.TenantID, UserID: input.Binding.UserID, AccountID: input.Change.AccountID})
				if err != nil || state.Access.User.Version != 2 || state.SocialLinkVersion != 2 || state.CredentialVersion != 2 || len(state.Access.Accounts) != 0 {
					t.Fatal("unlink did not retain authoritative tombstone and security versions", err)
				}
				passwordPresent := false
				for _, method := range state.Access.Methods {
					passwordPresent = passwordPresent || method.Credential.ID == "password-key" && method.Credential.Version == 1
				}
				if !passwordPresent {
					t.Fatal("unlink removed independent password storage")
				}
				var passwordEnabled bool
				if err := pool.Raw().QueryRow(ctx, `SELECT enabled FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id='password-key'`, seedArgs[:2]...).Scan(&passwordEnabled); err != nil || !passwordEnabled {
					t.Fatal("unlink disabled independent password storage", err)
				}
			}
			declaration.Contributors = registry.Descriptors()[:6]
			final := declaration
			final.Capability = &CapabilityPlan{CapabilityID: payload.ID, Purpose: capability.Purpose(payload.Operation), ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: issued.Proof.EnvelopeDigest(), ExpiresAt: payload.ExpiresAt, MaxUses: 1}
			issuance := CapabilityIssuancePlan{Contributor: issuer.Descriptor(), Grants: []CapabilityPlan{*final.Capability}}
			if mode == "public-preparation" {
				phase.generated, phase.declaration, phase.issuance = generated, final, issuance
				owner, err := NewAccountUnlinkUnitOfWork(c, repo, AccountUnlinkUnitOfWorkConfig{RetentionPolicyVersion: declaration.Audits[0].RetentionPolicyVersion})
				if err != nil {
					t.Fatal(err)
				}
				ready, err := owner.PrepareUnlink(ctx, original, declaration)
				if err != nil {
					t.Fatal("public native preparation failed", err)
				}
				prepared = &ready
				execute(Reservation{})
				replay, err := owner.PrepareUnlink(ctx, original, declaration)
				observation, ok := replay.Observation()
				if err != nil || !ok || observation.Outcome != identity.CommitOutcomeCommitted || observation.Unlink == nil || observation.Unlink.TombstoneVersion != 2 {
					t.Fatal("original public retry lost committed observation", err)
				}
				if _, ready := replay.Intent(); ready {
					t.Fatal("terminal replay obtained another execution handoff")
				}
				return
			}
			q, admitted, _, err := c.prepareAccountUnlinkPreparation(original, declaration)
			if err != nil {
				t.Fatal(err)
			}
			owner := [16]byte{1}
			r, _, err := c.startAccountUnlinkPreparation(ctx, original, q, admitted, phase, owner)
			if err != nil || !r.generate {
				t.Fatal("original preparation start", err)
			}
			wire := []byte("synthetic-authenticated-original-issuer-checkpoint")
			if err := c.retainFeaturePreparation(ctx, q, r.journal, owner, wire); err != nil {
				t.Fatal(err)
			}
			r.outputGeneration = r.journal.generation
			execution, final, err := c.prepareRestoredAccountUnlink(original, generated, declaration, final)
			if err != nil {
				t.Fatal("original-to-issued attachment validation", err)
			}
			if mode == "issuer-error" {
				issuer.mode = "error"
			}
			consumer.fail = mode == "reserve-error"
			if mode == "ack-before-commit" || mode == "ack-after-commit" {
				c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
					if mode == "ack-after-commit" {
						if err := tx.Commit(ctx); err != nil {
							return err
						}
					}
					return identity.UnavailableError{}
				}
			}
			reservation, attachErr := c.attachAccountUnlinkPreparation(ctx, q, execution, final, issuance, r, owner, wire)
			if mode == "success" || finalFailure || recoverAttached {
				if attachErr != nil || reservation.state == nil {
					t.Fatal("actual issuance-before-reservation attachment rejected", attachErr)
				}
				if _, err := accountUnlinkExecutionRequest(reservation.state); err != nil || reservation.state.plan.issuance != nil || len(reservation.state.plan.contributors) != 6 || !bytes.Equal(reservation.state.preparation.ciphertext, wire) || reservation.state.preparation.generation != 1 {
					t.Fatal("attachment lost original custody or enlisted issuer as domain evidence", err)
				}
			} else if attachErr == nil || reservation.state != nil {
				t.Fatal("failed/unacknowledged attachment granted execution custody")
			}
			var issuedRows, reservedRows, charges int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_issuance),(SELECT count(*) FROM public.unlink_prepared_capability),(SELECT count(*) FROM public.unlink_preparation_charge)`).Scan(&issuedRows, &reservedRows, &charges); err != nil {
				t.Fatal(err)
			}
			wantRows := 0
			if mode == "success" || mode == "ack-after-commit" || finalFailure || recoverAttached {
				wantRows = 1
			}
			if issuedRows != wantRows || reservedRows != wantRows || charges != 1 {
				t.Fatal("attachment issued/reserved a partial child or recharged original intent", issuedRows, reservedRows, charges)
			}
			if recoverAttached {
				raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
				result, err := c.recoverCommandReceipt(ctx, creationRecoveryQuery(input.Binding))
				if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, new(identity.UnavailableError)) {
					t.Fatal("unanimous negative expired unlink did not close original command", result.Outcome, err)
				}
				var state string
				var auditCount int
				var erased bool
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT state FROM public.unlink_prepared_capability),(SELECT count(*) FROM public.identity_test_audits WHERE no_change),(SELECT preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL FROM identity.commands WHERE command_id=$1)`, raw).Scan(&state, &auditCount, &erased); err != nil || state != "released" || auditCount != 2 || !erased {
					t.Fatal("negative recovery omitted exact release/audits/ciphertext erasure", err)
				}
				if work, err := c.Begin(ctx, reservation); err == nil || work.state != nil {
					t.Fatal("recovered generation permitted late original execution")
				}
				return
			}
			if mode == "success" || finalFailure {
				execute(reservation)
				return
			}
			issuer.mode, consumer.fail, c.preparationCommit = "", false, nil
			// Restart under a new command-key policy while retaining the original
			// verifier. The stored declaration/issuance must keep their provenance.
			c.keys.current = 2
			c.keys.retained[2] = [32]byte{2}
			q, admitted, _, err = c.prepareAccountUnlinkPreparation(original, declaration)
			if err != nil {
				t.Fatal("original intent cannot restart under retained-key policy", err)
			}
			execution, final, err = c.prepareRestoredAccountUnlink(original, generated, declaration, final)
			if err != nil {
				t.Fatal("original child cannot restore after key rotation", err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			nextOwner := [16]byte{2}
			next, _, err := c.startAccountUnlinkPreparation(ctx, original, q, admitted, phase, nextOwner)
			if err != nil || next.generate || next.outputGeneration != 1 || !bytes.Equal(next.output, wire) || next.journal.generation != 2 {
				t.Fatal("attachment retry regenerated or replaced original output", err)
			}
			beforeInvocations := issuer.invocations
			reservation, err = c.attachAccountUnlinkPreparation(ctx, q, execution, final, issuance, next, nextOwner, next.output)
			if err != nil || reservation.state == nil {
				t.Fatal("original retained attachment could not resume", err)
			}
			if mode == "ack-after-commit" && issuer.invocations != beforeInvocations {
				t.Fatal("committed original child was issued a second time")
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_issuance),(SELECT count(*) FROM public.unlink_prepared_capability),(SELECT count(*) FROM public.unlink_preparation_charge)`).Scan(&issuedRows, &reservedRows, &charges); err != nil || issuedRows != 1 || reservedRows != 1 || charges != 1 {
				t.Fatal("resumed original attachment duplicated child or protected attempt", err)
			}
			execute(reservation)
		})
	}
}
