package postgres

import (
	"context"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// Construction has no entropy or encryption. Reconstructing the exact same
// frozen declaration and bearer yields the same command intent; no placeholder
// digest/challenge is manufactured to enter the generated issuance schema.
// This private adapter input remains separate from the public Send request.
func (p *Contributor) mapSendRequest(ctx context.Context, request sendRequestRecord, binding identity.CommandBinding, bearer auth.BearerCredential) (identity.Command, error) {
	if ctx == nil || p == nil || p.codec == nil {
		return identity.Command{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return identity.Command{}, err
	}
	wire, err := encodeSendRequestRecord(request, binding)
	if err != nil {
		return identity.Command{}, err
	}
	defer clear(wire)
	op, err := boundIssuanceOperation(binding)
	if err != nil {
		return identity.Command{}, err
	}
	spec := identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{{Name: "otp.send-request", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}}}}
	b, _ := request.continuation.Bindings()
	var command identity.Command
	if _, ok := b.Authorization.AuthenticatedSession(); ok {
		command, err = identity.NewFeatureSessionCommand(spec, bearer)
	} else {
		command, err = identity.NewFeaturePreAuthCommand(spec, bearer)
	}
	if err != nil {
		return identity.Command{}, ErrInvalidCommand
	}
	if _, err := p.authenticateSendFlow(ctx, command, request.continuation, request.authority); err != nil {
		return identity.Command{}, err
	}
	return command, nil
}

func (p *Contributor) authenticateSendRequest(ctx context.Context, command identity.Command) (sendRequestRecord, nativeFlow, error) {
	bad := func(err error) (sendRequestRecord, nativeFlow, error) { return sendRequestRecord{}, nativeFlow{}, err }
	if ctx == nil || p == nil || p.codec == nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	spec, ok := command.Feature()
	op, opErr := boundIssuanceOperation(spec.Binding)
	if !ok || opErr != nil || spec.Operation != op || len(spec.Fields) != 1 ||
		spec.Fields[0].Name != "otp.send-request" || spec.Fields[0].Value.Kind != identity.FeatureBytes {
		return bad(ErrInvalidCommand)
	}
	if _, present := command.OneTimeCode(); present {
		return bad(ErrInvalidCommand)
	}
	request, err := decodeSendRequestRecord(spec.Fields[0].Value.Bytes, spec.Binding)
	if err != nil {
		return bad(err)
	}
	flow, err := p.authenticateSendFlow(ctx, command, request.continuation, request.authority)
	if err != nil {
		return bad(err)
	}
	return request, flow, nil
}
