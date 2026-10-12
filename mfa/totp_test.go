package mfa

import (
	"bytes"
	"testing"
)

// Independent published values: RFC 6238 (May 2011), Appendix B, with the
// SHA256/SHA512 key lengths specified by Appendix A. These public test keys
// are not enrollment material. https://www.rfc-editor.org/rfc/rfc6238
func TestTOTPRFC6238Vectors(t *testing.T) {
	times := []uint64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	want := [][]string{{"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"}, {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"}, {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}}
	keys := []string{"12345678901234567890", "12345678901234567890123456789012", "1234567890123456789012345678901234567890123456789012345678901234"}
	for a, algorithm := range []string{"SHA1", "SHA256", "SHA512"} {
		for i, now := range times {
			code, ok := totpCode([]byte(keys[a]), algorithm, 8, now/30)
			if !ok || !bytes.Equal(code, []byte(want[a][i])) {
				t.Fatal("published TOTP vector mismatch", algorithm, i)
			}
			clear(code)
		}
	}
}

func TestTOTPCodeBoundsAndLeadingZeros(t *testing.T) {
	for _, algorithm := range []string{"", "sha1", "MD5"} {
		if code, ok := totpCode(make([]byte, 20), algorithm, 6, 1); ok || code != nil {
			t.Fatal("unsupported algorithm accepted")
		}
	}
	for _, size := range []int{0, 19, 129} {
		if code, ok := totpCode(make([]byte, size), "SHA1", 6, 1); ok || code != nil {
			t.Fatal("unbounded key accepted")
		}
	}
	for _, digits := range []uint32{0, 5, 11, ^uint32(0)} {
		if code, ok := totpCode(make([]byte, 20), "SHA1", digits, 1); ok || code != nil {
			t.Fatal("unbounded digits accepted")
		}
	}
	code, ok := totpCode([]byte("12345678901234567890"), "SHA1", 6, 37037036)
	if !ok || !bytes.Equal(code, []byte("081804")) {
		t.Fatal("leading zero removed")
	}
	clear(code)
}
