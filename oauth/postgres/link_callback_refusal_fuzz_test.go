package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func FuzzRPProviderRefusalOutput(f *testing.F) {
	f.Add([]byte(nil), uint64(1))
	f.Add([]byte{1}, uint64(2))
	f.Add(bytes.Repeat([]byte{0xff}, 8193), uint64(1))
	f.Fuzz(func(t *testing.T, changes []byte, generation uint64) {
		if len(changes) > 16384 {
			return
		}
		start, retained, request, now := rpCallbackInputFixture(t)
		flow, err := start.service.authenticateRPCallback(t.Context(), request, retained.Binding, retained.StateProofCiphertext, *now)
		if err != nil {
			t.Fatal(err)
		}
		defer flow.destroy()
		spec, err := callbackSpecification(flow)
		if err != nil {
			t.Fatal(err)
		}
		spec.Counters = identity.AccountLinkCounterContext{Network: request.Network, PreparedAt: start.input.Started, KeyVersions: []uint32{1}}
		input, _ := request.Callback.Input()
		original, err := identity.NewAccountLinkPreparationCommand(spec, input, request.Session)
		if err != nil {
			t.Fatal(err)
		}
		phase := &rpLinkPhase{service: start.service, flow: flow, original: original}
		phase.input, err = phase.inputDigest(t.Context(), original)
		if err != nil {
			t.Fatal(err)
		}
		valid, err := phase.sealProviderRefusal(t.Context(), original, 1)
		if err != nil {
			t.Fatal(err)
		}
		wire := bytes.Clone(valid)
		for i, change := range changes {
			wire[i%len(wire)] ^= change
		}
		if len(changes) > 8192 {
			wire = append(wire, changes...)
		}
		got, err := phase.RestoreAccountLinkPreparationRefusal(t.Context(), spec.Binding, flow.statePlan, generation, wire)
		if err != nil {
			if got != (kernel.AccountLinkPreparationRefusal{}) {
				t.Fatal("invalid refusal leaked terminal evidence")
			}
			return
		}
		if got != (kernel.AccountLinkPreparationRefusal{}) && (generation != 1 || !bytes.Equal(valid, wire) || got.Binding != spec.Binding || got.State != flow.statePlan || got.Generation != 1) {
			t.Fatal("altered output/generation authenticated as original refusal")
		}
		if generation == 1 && bytes.Equal(valid, wire) && got == (kernel.AccountLinkPreparationRefusal{}) {
			t.Fatal("valid closed refusal was discarded")
		}
	})
}
