package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func TestQueryAuthenticatedCommandReturnsExactHistoricalReceipt(t *testing.T) {
	c, command, plan, _ := finalFeatureFixture(t)
	s, _ := command.Feature()
	authority, mint, original := finalProofFactory(t, s.Binding)
	proof := mint(original)
	c.finalAuthentication = &FinalAuthenticationConfig{Authority: authority, Namespace: "original-authority"}
	claim, frozen, _, _, err := c.prepareAuthenticated(s.Binding, command, proof, plan)
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
	wire, err := encodeFeaturePlan(s.Binding, fp, frozen)
	if err != nil {
		t.Fatal(err)
	}
	expected := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "original-audit", Feature: &identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: 0, AfterVersion: 1}}
	body, err := encodeJournalResult(claim, expected)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state, class, version := "committed", "committed", int32(1)
	observed := commandObservation{tenant: string(s.Binding.TenantID), purpose: s.Binding.OperationID, scope: claim.safeFields, state: &state, until: &now, now: now, resultVersion: &version, class: &class, result: body, plan: wire, fingerprint: fp[:], fingerprintKeyVersion: int64(c.keys.current)}
	_, caller := queryInputs(s.Binding)
	c.queryPolicy = &CommandQueryPolicy{Clock: finalProofClock{original.Proof.ExpiresAt.Add(time.Hour)}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	got, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, frozen, caller)
	if err != nil || got.Binding != expected.Binding || got.Outcome != expected.Outcome || got.AuditEventID != expected.AuditEventID || got.Feature == nil || *got.Feature != *expected.Feature {
		t.Fatal("historical issuance receipt lost", err)
	}
	got.Feature.AfterVersion = 99
	again, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, frozen, caller)
	if err != nil || again.Feature.AfterVersion != 1 {
		t.Fatal("receipt alias changed history")
	}
}

func authenticatedQueryFixture(t *testing.T) (*Coordinator, identity.Command, authentication.AuthenticatedProof, CommandPlan, commandObservation, authorization.DecisionContext, func(authentication.AuthenticatedProofSpec) authentication.AuthenticatedProof) {
	t.Helper()
	c, command, p, _ := finalFeatureFixture(t)
	s, _ := command.Feature()
	authority, mint, original := finalProofFactory(t, s.Binding)
	proof := mint(original)
	c.finalAuthentication = &FinalAuthenticationConfig{Authority: authority, Namespace: "original-authority"}
	claim, plan, _, _, err := c.prepareAuthenticated(s.Binding, command, proof, p)
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
	wire, err := encodeFeaturePlan(s.Binding, fp, plan)
	if err != nil {
		t.Fatal(err)
	}
	receipt := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}}
	body, err := encodeJournalResult(claim, receipt)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state, class, version := "committed", "committed", int32(1)
	observed := commandObservation{tenant: string(s.Binding.TenantID), purpose: s.Binding.OperationID, scope: claim.safeFields, state: &state, until: &now, now: now, resultVersion: &version, class: &class, result: body, plan: wire, fingerprint: fp[:], fingerprintKeyVersion: 1}
	_, caller := queryInputs(s.Binding)
	c.queryPolicy = &CommandQueryPolicy{Clock: finalProofClock{now}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	return c, command, proof, plan, observed, caller, mint
}

func TestQueryAuthenticatedCommandMatchesRetainedKeyAndRejectsChangedIntent(t *testing.T) {
	c, command, proof, plan, observed, caller, mint := authenticatedQueryFixture(t)
	s, _ := command.Feature()
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	c.keys.current = 2
	c.keys.retained[2] = [32]byte{2}
	rotated, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, proof, plan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, rotated, caller)
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.AuditEventID != "audit" {
		t.Fatal("original key rotation broke recovery", err)
	}
	original := proof.Bindings()
	for _, change := range []func(*authentication.AuthenticatedProofSpec){func(s *authentication.AuthenticatedProofSpec) { s.ProofVersion-- }, func(s *authentication.AuthenticatedProofSpec) { s.CredentialVersion-- }, func(s *authentication.AuthenticatedProofSpec) { s.CredentialID = "other" }, func(s *authentication.AuthenticatedProofSpec) {
		s.Proof.ExpiresAt = s.Proof.ExpiresAt.Add(time.Nanosecond)
	}} {
		changed := original
		change(&changed)
		other := mint(changed)
		p, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, other, rotated)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, other, p, caller)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || got.Outcome != identity.CommitOutcomeConflict || got.AuditEventID != "" {
			t.Fatal("changed proof adopted history", err)
		}
	}
	spec := s
	for i := range spec.Fields {
		if spec.Fields[i].Value.Kind == identity.FeatureText {
			spec.Fields[i].Value.Text = "changed"
			break
		}
	}
	other := featureCodecCommand(t, spec)
	p, err := c.PrepareAuthenticatedCommandPlan(s.Binding, other, proof, rotated)
	if err != nil {
		t.Fatal(err)
	}
	got, err = c.QueryAuthenticatedCommand(context.Background(), s.Binding, other, proof, p, caller)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || got.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("changed native intent adopted history", err)
	}
	modified := rotated
	modified.Audits = append([]AuditPlan(nil), rotated.Audits...)
	modified.Audits[0].RetentionPolicyVersion++
	modified, err = c.PrepareAuthenticatedCommandPlan(s.Binding, command, proof, modified)
	if err != nil {
		t.Fatal(err)
	}
	got, err = c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, modified, caller)
	if !errors.As(err, &conflict) || got.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("changed protected plan adopted history", err)
	}
	delete(c.keys.retained, 1)
	got, err = c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, rotated, caller)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || got != (identity.CommandResult{}) {
		t.Fatal("retired fingerprint key accepted", err)
	}
}

func TestQueryAuthenticatedCommandPreservesPolicyReadShapeAndDeniesUnprovedOutcomes(t *testing.T) {
	for _, mode := range []string{"denied", "policy-error", "policy-panic", "missing", "retired", "read-error", "bad-key-version", "missing-key", "corrupt-receipt"} {
		t.Run(mode, func(t *testing.T) {
			c, command, proof, plan, observed, caller, _ := authenticatedQueryFixture(t)
			s, _ := command.Feature()
			reads, decisions := 0, 0
			c.queryPolicy.Authorization = queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				decisions++
				if v, _ := dc.Request.Resource.Attributes["identity.command.recovery"].Bool(); !v {
					t.Fatal("missing recovery access policy")
				}
				switch mode {
				case "denied":
					return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
				case "policy-error":
					return authorization.Decision{}, errors.New("secret")
				case "policy-panic":
					panic("secret")
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
				reads++
				switch mode {
				case "missing":
					return commandObservation{}, pgx.ErrNoRows
				case "retired":
					observed.retired = true
				case "read-error":
					return commandObservation{}, errors.New("secret")
				case "bad-key-version":
					observed.fingerprintKeyVersion = 0
				case "missing-key":
					observed.fingerprintKeyVersion = 2
				case "corrupt-receipt":
					observed.result = []byte("bad")
				}
				return observed, nil
			}
			got, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, plan, caller)
			if err == nil || got != (identity.CommandResult{}) || reads != 1 || decisions != 1 {
				t.Fatal("unproved result escaped or decision/read shape changed", err)
			}
		})
	}
}

func TestQueryAuthenticatedCommandPreservesPendingAbortedAndRejectsForeignProof(t *testing.T) {
	for _, state := range []string{"pending", "aborted"} {
		t.Run(state, func(t *testing.T) {
			c, command, proof, plan, observed, caller, _ := authenticatedQueryFixture(t)
			s, _ := command.Feature()
			observed.state = &state
			if state == "pending" {
				observed.resultVersion = nil
				observed.class = nil
				observed.result = nil
				until := observed.now.Add(time.Second)
				observed.until = &until
			} else {
				class := "denied"
				observed.class = &class
				claim, _, _, _, err := c.prepareAuthenticated(s.Binding, command, proof, plan)
				if err != nil {
					t.Fatal(err)
				}
				observed.result, err = encodeJournalResult(claim, featureOutcome(s.Binding, &s.Operation, identity.CommitOutcomeNotCommitted, 0))
				if err != nil {
					t.Fatal(err)
				}
			}
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
			got, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, proof, plan, caller)
			if state == "pending" {
				if err != nil || got.Outcome != identity.CommitOutcomeInProgress || got.RetryAfter != time.Second {
					t.Fatal("pending changed", err)
				}
			} else {
				var forbidden identity.ForbiddenError
				if !errors.As(err, &forbidden) || got.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("aborted changed", err)
				}
			}
		})
	}
	c, command, proof, plan, _, caller, _ := authenticatedQueryFixture(t)
	s, _ := command.Feature()
	reads := 0
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		reads++
		return commandObservation{}, nil
	}
	_, foreignMint, foreignSpec := finalProofFactory(t, s.Binding)
	foreign := foreignMint(foreignSpec)
	for _, bad := range []authentication.AuthenticatedProof{{}, foreign} {
		if _, err := c.QueryAuthenticatedCommand(context.Background(), s.Binding, command, bad, plan, caller); err == nil {
			t.Fatal("foreign provenance accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.QueryAuthenticatedCommand(ctx, s.Binding, command, proof, plan, caller); err == nil {
		t.Fatal("cancelled query read")
	}
	if reads != 0 {
		t.Fatal("invalid admission reached primary")
	}
}

func TestRecoverAuthenticatedCommandDoesNotReserveMissingOrReplayCommittedCommand(t *testing.T) {
	c, command, proof, plan, observed, caller, _ := authenticatedQueryFixture(t)
	s, _ := command.Feature()
	reads := 0
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { reads++; return observed, nil }
	got, err := c.RecoverAuthenticatedCommand(context.Background(), s.Binding, command, proof, plan, caller)
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.AuditEventID != "audit" || reads != 1 {
		t.Fatal("terminal recovery did not remain pure", err)
	}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		return commandObservation{}, pgx.ErrNoRows
	}
	got, err = c.RecoverAuthenticatedCommand(context.Background(), s.Binding, command, proof, plan, caller)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || got != (identity.CommandResult{}) {
		t.Fatal("missing command was reserved or called not committed", err)
	}
}

func TestRecoverAuthenticatedCommandPreservesUnknownOnFailedPendingReconciliation(t *testing.T) {
	c, command, proof, plan, observed, caller, _ := authenticatedQueryFixture(t)
	s, _ := command.Feature()
	state := "pending"
	until := observed.now.Add(time.Second)
	observed.state = &state
	observed.until = &until
	observed.resultVersion = nil
	observed.class = nil
	observed.result = nil
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	// The exact pending receipt was read, but the coordinator fixture has no
	// primary pool for subsequent reconciliation. Failure cannot prove rollback.
	got, err := c.RecoverAuthenticatedCommand(context.Background(), s.Binding, command, proof, plan, caller)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || got.Outcome != identity.CommitOutcomeUnknown || got.Binding != s.Binding || got.Validate() != nil {
		t.Fatal("failed reconciliation lost scoped unknown outcome", err)
	}
}
