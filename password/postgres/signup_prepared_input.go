package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const maximumSignupInput = 1 << 20

// Original input is code-free. Only the original mapping's winning selected
// account, approved fields and primary flow are retained. This is not field
// permission or live account/flow authority; final Work must fence them again.
// Explicit scalar projection is confined to the authenticated native codec.
type signupPreparedInput struct {
	Schema       uint8
	Binding      identity.CommandBinding
	Creation     signupStoredCreation
	Identifier   identity.Identifier
	Credential   identity.CredentialRef
	Comparison   string
	Flow         signupOriginalFlow
	RequestInput []identity.FeatureField
	OccurredAt   time.Time
	Username     *identity.Identifier `json:",omitempty"`
}

// Byte projections keep valid UTF-8 strings lossless while bounding JSON's
// expansion to base64 rather than six bytes per control character. The source
// contract admits 256 KiB of strings and up to 128 fields including defaults.
// Do not shrink that contract to accommodate the journal's 1 MiB ciphertext.
type signupStoredCreation struct {
	Binding    identity.CommandBinding
	Status     identity.Status
	Attributes []signupStoredAttribute
}

type signupStoredAttribute struct {
	Name  string
	Kind  identity.AttributeKind
	Text  []byte     `json:",omitempty"`
	Bool  bool       `json:",omitempty"`
	Int64 int64      `json:",omitempty"`
	Time  *time.Time `json:",omitempty"`
	List  [][]byte   `json:",omitempty"`
}

func storeSignupCreation(s identity.CreateUserCommand) signupStoredCreation {
	out := signupStoredCreation{Binding: s.Binding, Status: s.Status}
	if s.Attributes != nil {
		out.Attributes = make([]signupStoredAttribute, len(s.Attributes))
	}
	for i, a := range s.Attributes {
		v := signupStoredAttribute{Name: a.Name, Kind: a.Value.Kind, Bool: a.Value.Scalar.Bool, Int64: a.Value.Scalar.Int64}
		switch a.Value.Kind {
		case identity.AttributeString:
			v.Text = []byte(a.Value.Scalar.String)
		case identity.AttributeTime:
			at := a.Value.Scalar.Time
			v.Time = &at
		case identity.AttributeStringList:
			v.List = make([][]byte, len(a.Value.List))
			for n, s := range a.Value.List {
				v.List[n] = []byte(s.String)
			}
		}
		out.Attributes[i] = v
	}
	return out
}

func restoreSignupCreation(s signupStoredCreation) (identity.CreateUserCommand, error) {
	bad := func() (identity.CreateUserCommand, error) {
		return identity.CreateUserCommand{}, password.ErrPasswordWork
	}
	out := identity.CreateUserCommand{Binding: s.Binding, Status: s.Status}
	if len(s.Attributes) > 128 {
		return bad()
	}
	if s.Attributes != nil {
		out.Attributes = make([]identity.AttributeUpdate, len(s.Attributes))
	}
	for i, a := range s.Attributes {
		v := identity.AttributeValue{Kind: a.Kind}
		if a.Kind == identity.AttributeStringList {
			if a.Text != nil || a.Bool || a.Int64 != 0 || a.Time != nil || len(a.List) > 64 {
				return bad()
			}
			v.List = make([]identity.AttributeScalar, len(a.List))
			for n, s := range a.List {
				v.List[n] = identity.AttributeScalar{Kind: identity.AttributeString, String: string(s)}
			}
		} else {
			if a.List != nil {
				return bad()
			}
			v.Scalar = identity.AttributeScalar{Kind: a.Kind, String: string(a.Text), Bool: a.Bool, Int64: a.Int64}
			if a.Time != nil {
				v.Scalar.Time = *a.Time
			}
		}
		out.Attributes[i] = identity.AttributeUpdate{Name: a.Name, Value: v}
	}
	// The root owner validates discriminants, inactive fields, UTF-8, names,
	// cardinality and the complete admitted string budget before any use.
	command, err := identity.NewUserCreationCommand(out)
	if err != nil {
		return bad()
	}
	creation, _ := command.CreateUser()
	return creation, nil
}

func validateSignupPreparedInput(k kernel.RequestKeyPreparationBinding, profile [32]byte, input signupPreparedInput, current identity.RequestIntent) (kernel.PasswordRegistrationIntent, session.PreAuthTransaction, error) {
	bad := func() (kernel.PasswordRegistrationIntent, session.PreAuthTransaction, error) {
		return kernel.PasswordRegistrationIntent{}, session.PreAuthTransaction{}, password.ErrPasswordWork
	}
	b := input.Binding
	if input.Schema != 1 || !signupOperation(k.Feature.Operation) || b.ValidateFor(k.Feature.Operation) != nil || (b.OperationID == "identity.username.signup") != (input.Username != nil) || k.Scope.RouteID != b.OperationID || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.PolicyVersion != k.PolicyVersion || b.CorrelationID != string(b.CommandID) || b.PolicyID != input.Flow.Policy || b.AnonymousFlowID != string(input.Flow.ID) || input.Flow.Tenant != b.TenantID || input.Flow.Action != b.OperationID || input.Flow.PolicyVersion != b.PolicyVersion || input.OccurredAt.IsZero() || input.OccurredAt.Before(input.Flow.IssuedAt) || !input.OccurredAt.Before(input.Flow.ExpiresAt) {
		return bad()
	}
	storedCreation, err := restoreSignupCreation(input.Creation)
	if err != nil {
		return bad()
	}
	creation := storedCreation.Binding
	expected := b
	expected.AnonymousFlowID, expected.OperationID = "", "identity.user.create"
	expected.UserID, expected.SchemaID, expected.SchemaVersion = creation.UserID, creation.SchemaID, creation.SchemaVersion
	if creation != expected || input.Creation.Status != identity.StatusActive {
		return bad()
	}
	selected := kernel.PasswordRegistrationIntent{Creation: storedCreation, Identifier: input.Identifier, Credential: input.Credential, ComparisonProfile: input.Comparison}
	if input.Username != nil {
		selected.Username = *input.Username
	}
	if _, err := kernel.PasswordRegistrationFields(selected); err != nil {
		return bad()
	}
	stored, err := identity.NewRequestIntent(input.RequestInput)
	fields, valid := stored.Fields()
	actual, present := current.Fields()
	if err != nil || !valid || !present || len(fields) != 4 || !reflect.DeepEqual(fields, actual) {
		return bad()
	}
	for _, f := range fields {
		if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) != 32 {
			return bad()
		}
		switch f.Name {
		case "profile":
			if !bytes.Equal(f.Value.Bytes, profile[:]) {
				return bad()
			}
		case "password", "cookie", "input":
		default:
			return bad()
		}
	}
	flow, err := signupFlowState(input.Flow)
	if err != nil {
		return bad()
	}
	// Structural command construction freezes nested caller-owned field lists.
	command, err := identity.NewUserCreationCommand(selected.Creation)
	if err != nil {
		return bad()
	}
	selected.Creation, _ = command.CreateUser()
	return selected, flow, nil
}

func (r *Repository) retainSignupInput(ctx context.Context, crypto *envelope.Service, key string, k kernel.RequestKeyPreparationBinding, profile [32]byte, b identity.CommandBinding, selected kernel.PasswordRegistrationIntent, flow session.PreAuthTransaction, intent identity.RequestIntent, at time.Time) ([]byte, error) {
	if ctx == nil || crypto == nil {
		return nil, password.ErrPasswordWork
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	aad, err := r.signupInputAAD(k, profile)
	if err != nil {
		return nil, err
	}
	projection, err := signupFlowProjection(flow)
	if err != nil {
		return nil, err
	}
	fields, ok := intent.Fields()
	if !ok {
		return nil, password.ErrPasswordWork
	}
	if _, err := kernel.PasswordRegistrationFields(selected); err != nil {
		return nil, password.ErrPasswordWork
	}
	input := signupPreparedInput{Schema: 1, Binding: b, Creation: storeSignupCreation(selected.Creation), Identifier: selected.Identifier, Credential: selected.Credential, Comparison: selected.ComparisonProfile, Flow: projection, RequestInput: fields, OccurredAt: at.UTC()}
	if selected.Username != (identity.Identifier{}) {
		name := selected.Username
		input.Username = &name
	}
	frozen, _, err := validateSignupPreparedInput(k, profile, input, intent)
	if err != nil {
		return nil, err
	}
	input.Creation = storeSignupCreation(frozen.Creation)
	plain, err := json.Marshal(input)
	defer clear(plain)
	if err != nil || len(plain) > maximumSignupInput-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: key, Context: aad})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumSignupInput {
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

func (r *Repository) openSignupInput(ctx context.Context, crypto *envelope.Service, k kernel.RequestKeyPreparationBinding, profile [32]byte, wire []byte) (signupPreparedInput, error) {
	bad := func(err error) (signupPreparedInput, error) {
		return signupPreparedInput{}, err
	}
	if ctx == nil || crypto == nil || len(wire) == 0 || len(wire) > maximumSignupInput {
		return bad(password.ErrPasswordWork)
	}
	if ctx.Err() != nil {
		return bad(ctx.Err())
	}
	aad, err := r.signupInputAAD(k, profile)
	if err != nil {
		return bad(err)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad(password.ErrPasswordWork)
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if ctx.Err() != nil {
		return bad(ctx.Err())
	}
	if err != nil || len(plain) == 0 || len(plain) > maximumSignupInput-4096 {
		return bad(password.ErrPasswordWork)
	}
	var input signupPreparedInput
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		return bad(password.ErrPasswordWork)
	}
	canonical, err := json.Marshal(input)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return bad(password.ErrPasswordWork)
	}
	return input, nil
}

func (r *Repository) restoreSignupInput(ctx context.Context, crypto *envelope.Service, k kernel.RequestKeyPreparationBinding, profile [32]byte, wire []byte, intent identity.RequestIntent) (identity.CommandBinding, kernel.PasswordRegistrationIntent, session.PreAuthTransaction, time.Time, error) {
	input, err := r.openSignupInput(ctx, crypto, k, profile, wire)
	return signupInputResult(k, profile, input, intent, err)
}

// Historical recovery authenticates the stored commitments instead of asking
// the client to reconstruct password-derived input. It does not grant execution
// or disclosure: the native recovery service must separately check original
// cookie possession and current kernel disclosure/reconciliation authority.
func (r *Repository) recoverSignupInput(ctx context.Context, crypto *envelope.Service, k kernel.RequestKeyPreparationBinding, profile [32]byte, wire []byte) (identity.CommandBinding, kernel.PasswordRegistrationIntent, session.PreAuthTransaction, time.Time, error) {
	input, err := r.openSignupInput(ctx, crypto, k, profile, wire)
	intent, intentErr := identity.NewRequestIntent(input.RequestInput)
	if err == nil {
		err = intentErr
	}
	return signupInputResult(k, profile, input, intent, err)
}

func signupInputResult(k kernel.RequestKeyPreparationBinding, profile [32]byte, input signupPreparedInput, intent identity.RequestIntent, err error) (identity.CommandBinding, kernel.PasswordRegistrationIntent, session.PreAuthTransaction, time.Time, error) {
	if err == nil {
		var selected kernel.PasswordRegistrationIntent
		var flow session.PreAuthTransaction
		selected, flow, err = validateSignupPreparedInput(k, profile, input, intent)
		if err == nil {
			return input.Binding, selected, flow, input.OccurredAt, nil
		}
	}
	return identity.CommandBinding{}, kernel.PasswordRegistrationIntent{}, session.PreAuthTransaction{}, time.Time{}, err
}
