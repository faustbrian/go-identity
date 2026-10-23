//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresOTPAuthenticatedActionProof(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true}, true)
}

func TestReferencePostgresOTPAuthenticatedFactorRename(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true}, true)
}

func TestReferencePostgresOTPFactorRenameCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, completionCommitFault: true}, true)
}

func TestReferencePostgresOTPActiveAttemptBudget(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPActiveCase: "budget"}, true)
}
func TestReferencePostgresOTPActiveChallengeExpiresAfterLock(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPActiveCase: "challenge-expiry"}, true)
}
func TestReferencePostgresOTPActiveObservationIsNotRenewed(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPActiveCase: "observation-expiry", completionCommitFault: true}, true)
}

func configureReferenceMFAOTPActive(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{216}, ed25519.SeedSize))
	defer clear(key)
	signing, err := mfapg.NewFactorVerificationSigningKey("reference-otp-factor-proof", key)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeStepUp, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.MFAOTPEnrollment.ActiveStepUp = &reference.MFAOTPActiveStepUpConfiguration{Native: mfapg.OTPActiveStepUpConfig{AllowedOrigins: []string{origin}, AttemptKeyVersion: 7, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"reference-otp-factor-proof": key.Public().(ed25519.PublicKey)}, Issuer: origin, Environment: "reference", Audience: "reference-mfa-factor-update", TTL: time.Minute}, Policy: policy}
}

func proveReferenceMFAOTPActive(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, bearer, csrfWire, origin string, factor mfa.FactorID, user identity.UserID, messages <-chan string, previous mfa.OTPAuthenticatedStepUp) string {
	t.Helper()
	service, err := features.MFAOTPActiveStepUp()
	if err != nil {
		t.Fatal("selected active OTP public handle unavailable", err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.mfa.otp-send", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	key, _ := identity.NewIdempotencyKey([]byte("reference-otp-active-send"))
	custody := mfa.OTPAuthenticatedStepUp{Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Purpose: "identity.mfa.factor-update"}
	r := mfa.OtpSendRequest{TenantID: otpTenant, FactorID: factor, Channel: delivery.ChannelEmail, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key, StepUp: &custody}
	sent, err := service.OtpSend(ctx, r)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted || sent.CommandID == "" || sent.DeliveryState != delivery.StateQueued {
		if sent.CommandID != "" {
			command, _ := base64.RawURLEncoding.DecodeString(string(sent.CommandID))
			var state string
			var started, output bool
			if readErr := f.pool.Raw().QueryRow(ctx, `SELECT state,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1`, command).Scan(&state, &started, &output); readErr == nil {
				t.Logf("active send journal state=%s generation_started=%t output_retained=%t", state, started, output)
			}
		}
		t.Fatalf("real OTP session could not queue active factor challenge: error=%v outcome=%v command_present=%t", err, sent.Outcome, sent.CommandID != "")
	}
	repeat, err := service.OtpSend(ctx, r)
	if err != nil || repeat.Outcome != identity.CommitOutcomeCommitted || repeat.CommandID != sent.CommandID {
		t.Fatal("active send keyed retry changed original issuance", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("active OTP actual delivery worker", err)
	}
	var raw string
	select {
	case raw = <-messages:
	case <-ctx.Done():
		t.Fatal("active OTP delivery not captured")
	}
	wrong := "000000"
	if raw == wrong {
		wrong = "000001"
	}
	code, err := auth.NewOneTimeCode(wrong)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := identity.NewCommandID()
	caller.Request.Action = "identity.mfa.otp-verify"
	custody.SendCommandID = sent.CommandID
	check := mfa.OtpVerifyRequest{TenantID: otpTenant, CommandID: command, FactorID: factor, Code: code, Caller: caller, Origin: origin, Network: "127.0.0.1", StepUp: &custody}
	valid := check
	valid.Code, err = auth.NewOneTimeCode(raw)
	if err != nil {
		t.Fatal(err)
	}
	switch f.mfaOTPActiveCase {
	case "budget":
		proveOTPActiveBudget(t, ctx, f, service, valid, wrong)
		return ""
	case "challenge-expiry":
		proveOTPActiveLockExpiry(t, ctx, f, service, valid)
		return ""
	case "observation-expiry":
		proveOTPActiveObservationExpiry(t, ctx, f, features, service, valid)
		return ""
	}
	proveOTPActiveCustodyDenials(t, ctx, f, service, valid, previous)
	if out, err := service.OtpVerify(ctx, check); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("wrong delivered code created factor action proof", err)
	}
	check.CommandID, _ = identity.NewCommandID()
	check.Code, err = auth.NewOneTimeCode(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.OtpVerify(ctx, check)
	proof := out.StepUpProof.Bindings()
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || proof.Proof.ID != auth.ProofID(check.CommandID) || proof.Proof.Method != "otp" || proof.Proof.Purpose != "identity.mfa.factor-update" || proof.SessionID == "" || proof.SessionVersion == 0 {
		command, _ := base64.RawURLEncoding.DecodeString(string(check.CommandID))
		var state string
		var started, output bool
		if e := f.pool.Raw().QueryRow(ctx, `SELECT state,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1`, command).Scan(&state, &started, &output); e == nil {
			t.Logf("active verify journal state=%s generation_started=%t output_retained=%t", state, started, output)
		}
		t.Fatal("actual delivered OTP did not produce action-bound factor evidence", err)
	}
	source, err := mfapg.NewOTPFactorVerificationSource(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := source.Reauthentication(ctx, proof.Proof.ID)
	frame, frameErr := stored.SigningBytes()
	defer clear(frame)
	keys := f.config.MFAOTPEnrollment.ActiveStepUp.Native.VerificationKeys
	if err != nil || frameErr != nil || stored.Proof != proof || stored.CredentialID != string(factor) || !ed25519.Verify(keys[stored.KeyID], frame, stored.Signature) {
		t.Fatal("OTP proof did not retain original independent signature/source", err)
	}
	if replay, err := service.OtpVerify(ctx, check); err == nil && replay.Outcome != identity.CommitOutcomeCommitted || replay.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("OTP verification retry changed outcome or redelivered proof", err)
	}
	check.CommandID, _ = identity.NewCommandID()
	if replay, err := service.OtpVerify(ctx, check); err == nil || replay.Outcome == identity.CommitOutcomeCommitted || replay.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("consumed active OTP authorized another proof")
	}
	if f.config.MFAOTPEnrollment.ActiveStepUp.FactorManagement != nil {
		token, err := session.ParseToken(bearer)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		management, err := features.MFAOTPFactorManagement()
		if err != nil {
			t.Fatal("selected OTP management unavailable", err)
		}
		listing, err := features.MFAListing()
		if err != nil {
			t.Fatal(err)
		}
		caller.Request.Action = "identity.mfa.list"
		before, err := listing.List(ctx, mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "otp-rename-before"})
		if err != nil {
			t.Fatal("pre-rename safe inventory", err)
		}
		var version uint64
		for _, item := range before.Factors {
			if item.ID == factor {
				version = item.Version
			}
		}
		if version == 0 {
			t.Fatal("confirmed OTP missing from inventory")
		}
		caller.Request.Action = "identity.mfa.factor-update"
		key, _ := identity.NewIdempotencyKey([]byte("reference-otp-factor-rename"))
		request := mfa.FactorUpdateRequest{TenantID: otpTenant, FactorID: factor, Action: mfa.Rename, Name: "mail factor <work>", ExpectedVersion: version, FactorProof: proof.Proof, Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key}
		if f.mfaOTPRemoval {
			request.Action, request.Name = mfa.Remove, ""
			proveOTPRemovalRecoveryDenials(t, ctx, f, management, request)
		}
		proveOTPFactorRenameDenials(t, ctx, f, management, request)
		proveOTPFactorRenameRollback(t, ctx, f, management, request)
		if f.completionFault != nil {
			f.completionFault.armed.Store(true)
		}
		var updated mfa.FactorUpdateResult
		if f.mfaOTPRemovalRace {
			updated, request.IdempotencyKey = proveOTPRemovalCompetingCommands(t, ctx, management, request)
		} else {
			updated, err = management.FactorUpdate(ctx, request)
		}
		if f.completionFault != nil {
			if err == nil || updated.Outcome != identity.CommitOutcomeUnknown || updated.CommandID == "" || updated.Factor.ID != "" || !f.completionFault.hit.Load() {
				t.Fatal("lost OTP rename acknowledgement lost uncertainty or disclosed metadata", updated.Outcome, err)
			}
		} else if err != nil || updated.Outcome != identity.CommitOutcomeCommitted || updated.Factor.ID != factor || updated.Factor.Method != "otp" || updated.Factor.Label != request.Name || updated.Factor.Version != version+1 {
			t.Fatal("OTP factor rename did not commit", err)
		}
		request.CommandID = updated.CommandID
		query := identity.RecoveryQuery{TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.factor-update", CommandID: updated.CommandID}
		if recovered, e := management.RecoverFactorUpdate(ctx, query, caller); e != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Factor.ID != "" {
			t.Fatal("OTP rename recovery did not conserve original metadata-only outcome", e)
		}
		if replay, e := management.FactorUpdate(ctx, request); e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.CommandID != updated.CommandID || replay.Factor.ID != "" {
			t.Fatal("OTP rename retry repeated mutation or disclosed metadata", e)
		}
		sessions, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err == nil && got.Authenticated {
			t.Fatal("factor rename retained old source session")
		}
		if f.mfaOTPRemoval {
			proveOTPRemovalState(t, ctx, f, factor, user, updated.CommandID)
			before := otpManagementState(t, ctx, f)
			fresh := request
			fresh.CommandID = ""
			fresh.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-removed-factor-fresh-command"))
			if out, e := management.FactorUpdate(ctx, fresh); e == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Factor.ID != "" || otpManagementState(t, ctx, f) != before {
				t.Fatal("fresh command reused removed-factor custody or changed protected state", e)
			}
		}
		return request.Name
	}
	return ""
}
