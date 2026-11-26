package onetap

import (
	"strings"
	"testing"
)

func FuzzCSRF(f *testing.F) {
	for _, pair := range [][2]string{{"same", "same"}, {"a", "b"}, {"", ""}, {" x", " x"}, {"a;b", "a;b"}, {strings.Repeat("x", 1024), strings.Repeat("x", 1024)}, {strings.Repeat("x", 1025), strings.Repeat("x", 1025)}} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		got := validCSRF([]string{a}, []string{b})
		if got && (a != b || !csrfValue(a) || !csrfValue(b)) {
			t.Fatal("invalid or unequal CSRF accepted")
		}
		if a == b && csrfValue(a) && !got {
			t.Fatal("canonical equal CSRF denied")
		}
		if validCSRF([]string{a, a}, []string{b}) || validCSRF([]string{a}, []string{b, b}) || validCSRF(nil, []string{b}) {
			t.Fatal("duplicate or absent value accepted")
		}
	})
}

func TestCanonicalOriginSelectedProfile(t *testing.T) {
	for _, origin := range []string{"https://app.test", "https://app.test:8443", "https://127.0.0.1"} {
		if !canonicalOrigin(origin) {
			t.Fatal("canonical HTTPS origin denied")
		}
	}
	for _, origin := range []string{"https://app.test:", "https://app.test:0443", "https://app.test:65536", "https://app.test.", "https://app..test", "https://-app.test", "https://[::1]", "https://app.test/%2f", "https://app.test?x=1", "https://app.test#x", "https://app.test:0"} {
		if canonicalOrigin(origin) {
			t.Fatal("unsupported origin accepted")
		}
	}
}

func TestCanonicalOriginRejectsSpecialIPv4Aliases(t *testing.T) {
	for _, host := range []string{"127.1", "2130706433", "0x7f000001", "127.000.0.1", "999.999.999.999", "127.0.0.01", "0177.0.0.1", "127.0.0.0x1", "app.123", "app.0xff", "0x", "4294967296"} {
		t.Run(host, func(t *testing.T) {
			if canonicalOrigin("https://" + host) {
				t.Fatal("browser-normalized or invalid special IPv4 host admitted")
			}
		})
	}
	for _, host := range []string{"127.0.0.1", "192.0.2.1", "255.255.255.255", "0.0.0.0", "app.test", "example.com", "app.0xgg", "123.example", "0xff.example"} {
		if !canonicalOrigin("https://" + host) {
			t.Fatal("canonical dotted IPv4 or real DNS host denied")
		}
	}
}
