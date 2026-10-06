package session

import "testing"

func FuzzEncryptedCacheProjection(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Schema":1,"Schema":1}`))
	f.Add([]byte(`{"Session":{"Lookup":{"Sum":[null]}}}`))
	c := &EncryptedCacheCodec{service: &SessionService{config: ServiceConfig{Audience: "audience"}}, config: EncryptedCacheConfig{MaximumBytes: 32768}}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 32769 {
			b = b[:32769]
		}
		restored := c.restore(b, "tenant")
		if restored.state != nil {
			r := restored.state.result
			if !r.Authenticated || r.validity == nil || r.validity.owner != c.service || r.validity.until.After(r.validity.acceptedAt.Add(20e9)) {
				t.Fatal("invalid reconstructed custody")
			}
		}
	})
}
