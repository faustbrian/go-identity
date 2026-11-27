package postgres

import "testing"

func TestProxyLookupDigestIsExactAcrossDeploymentAndRetainedKey(t *testing.T) {
	state, key := [32]byte{1}, [32]byte{2}
	want := proxyLookupDigest(key, 1, "production-a", "provider-a", 1, state)
	if want == ([32]byte{}) || want == state || want != proxyLookupDigest(key, 1, "production-a", "provider-a", 1, state) {
		t.Fatal("the same native callback cannot recover its exact private lookup")
	}
	for _, changed := range [][32]byte{
		proxyLookupDigest([32]byte{3}, 1, "production-a", "provider-a", 1, state),
		proxyLookupDigest(key, 2, "production-a", "provider-a", 1, state),
		proxyLookupDigest(key, 1, "production-b", "provider-a", 1, state),
		proxyLookupDigest(key, 1, "production-a", "provider-b", 1, state),
		proxyLookupDigest(key, 1, "production-a", "provider-a", 2, state),
		proxyLookupDigest(key, 1, "production-a", "provider-a", 1, [32]byte{4}),
	} {
		if changed == want || changed == ([32]byte{}) {
			t.Fatal("foreign provider callback shares an original locator")
		}
	}
}
