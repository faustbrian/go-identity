package mfapostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// No owner callback may run before the coordinator supplies invocation custody.
type oneTapFactorUnownedInvocation struct{}

func (*oneTapFactorUnownedInvocation) Descriptor() kernel.ContributorDescriptor {
	panic("unowned factor guard consulted contributor")
}

func (*oneTapFactorUnownedInvocation) FeatureOperations() []identity.FeatureOperation {
	panic("unowned factor guard consulted contributor")
}

func (*oneTapFactorUnownedInvocation) ValidateFeatureCommand(identity.Command, kernel.CommandPlan) error {
	panic("unowned factor guard consulted contributor")
}

func (*oneTapFactorUnownedInvocation) ApplyFeature(context.Context, kernel.Work, identity.Command) (identity.FeatureReceipt, error) {
	panic("unowned factor guard invoked contributor")
}

func (*oneTapFactorUnownedInvocation) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	panic("unowned factor guard invoked contributor")
}

func TestRequireOneTapCallbackFactorsRejectsUnownedInvocation(t *testing.T) {
	owner := &oneTapFactorUnownedInvocation{}
	for _, item := range []struct {
		name    string
		ctx     context.Context
		owner   kernel.FeatureExecutionContributor
		version uint64
	}{
		{name: "nil context", owner: owner, version: 1},
		{name: "nil owner", ctx: t.Context(), version: 1},
		{name: "zero generation", ctx: t.Context(), owner: owner},
		{name: "missing Work", ctx: t.Context(), owner: owner, version: 1},
	} {
		t.Run(item.name, func(t *testing.T) {
			state, err := RequireOneTapCallbackFactors(item.ctx, kernel.Work{}, item.owner, identity.Command{}, item.version)
			if err == nil || state.Version() != 0 {
				t.Fatal("unowned callback acquired factor authority", err)
			}
		})
	}
}

func TestRequireOneTapCallbackFactorsPreservesCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer stop()
	for _, item := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "cancelled", ctx: cancelled, want: context.Canceled},
		{name: "expired", ctx: expired, want: context.DeadlineExceeded},
	} {
		t.Run(item.name, func(t *testing.T) {
			state, err := RequireOneTapCallbackFactors(item.ctx, kernel.Work{}, &oneTapFactorUnownedInvocation{}, identity.Command{}, 1)
			if !errors.Is(err, item.want) || state.Version() != 0 {
				t.Fatal("callback factor guard lost cancellation", err)
			}
		})
	}
}

func oneTapFactorCommandSpec(t *testing.T) identity.FeatureCommandSpec {
	t.Helper()
	account := kernel.ProviderAccountAdmission{
		Account: identity.Account{
			ID: "google-account", TenantID: "tenant-a", UserID: "selected-user",
			Provider: "google", Issuer: "https://accounts.google.com", Subject: "opaque-subject", Version: 5,
		},
		SocialLinkVersion: 7,
		Credential: kernel.CredentialAdmission{
			Credential: identity.CredentialRef{
				ID: "provider-ref", TenantID: "tenant-a", UserID: "selected-user",
				Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 11,
			},
			UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19,
		},
	}
	fields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		t.Fatal("original Google account snapshot", err)
	}
	op := kernel.OneTapCallbackOperation()
	return identity.FeatureCommandSpec{
		Operation: op,
		Binding: identity.CommandBinding{
			CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a",
			ActorID: "one-tap-service", ActorKind: authorization.SubjectServiceAccount,
			AnonymousFlowID: "original-flow", RecordID: "original-flow",
			OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
			PolicyID: "one-tap-signin", PolicyVersion: 1, CorrelationID: "one-tap-correlation",
		},
		Fields: fields,
	}
}

func TestRequireOneTapCallbackFactorsCannotPromoteAccountSnapshot(t *testing.T) {
	for _, mode := range []string{"exact One Tap", "metadata only", "session token", "ordinary OAuth", "foreign flow", "foreign tenant"} {
		t.Run(mode, func(t *testing.T) {
			spec := oneTapFactorCommandSpec(t)
			credential := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			var command identity.Command
			var err error
			switch mode {
			case "metadata only":
				command, err = identity.NewFeatureCommand(spec)
			case "session token":
				command, err = identity.NewFeatureSessionCommand(spec, credential)
			default:
				switch mode {
				case "ordinary OAuth":
					spec.Operation = identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
					spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
					spec.Binding.RecordID = ""
				case "foreign flow":
					spec.Binding.RecordID = "other-flow"
				case "foreign tenant":
					spec.Binding.TenantID = "other-tenant"
				}
				command, err = identity.NewFeaturePreAuthCommand(spec, credential)
			}
			if err != nil {
				t.Fatal("callback custody fixture", err)
			}
			if mode == "exact One Tap" {
				if _, err := kernel.OneTapCallbackAccount(command); err != nil {
					t.Fatal("exact Google snapshot fixture", err)
				}
			}
			state, err := RequireOneTapCallbackFactors(t.Context(), kernel.Work{}, &oneTapFactorUnownedInvocation{}, command, 1)
			if err == nil || state.Version() != 0 {
				t.Fatal("account metadata without original Work acquired factor authority", err)
			}
		})
	}
}
