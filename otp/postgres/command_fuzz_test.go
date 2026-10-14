package postgres

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-identity/otp"
)

func FuzzAttemptRecord(f *testing.F) {
	a, s := mappedAttempt(f, otp.PurposeSignin, false)
	i, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	record, err := i.SealForCommand(a)
	if err != nil {
		f.Fatal(err)
	}
	seed := encodeAttemptRecord(record)
	for _, data := range [][]byte{seed, nil, []byte(recordPrefix), append(bytes.Clone(seed), 0), bytes.Repeat([]byte{0xff}, 4097)} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := decodeAttemptRecord(data, s.Binding, s.Operation)
		if err != nil {
			return
		}
		if len(data) > 4096 || !bytes.Equal(data, encodeAttemptRecord(r)) {
			t.Fatal("accepted noncanonical native record")
		}
	})
}
