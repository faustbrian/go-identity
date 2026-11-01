package oauth

import (
	"io"
	"sync"
	"testing"
)

func TestRequestBodyCloseOwnsErasureAndDeniesLaterReads(t *testing.T) {
	raw := []byte("original-request-secret")
	body := newTokenRequestBody(raw)
	read := make([]byte, 8)
	if n, err := body.Read(read); n != 8 || err != nil {
		t.Fatal("bounded request read failed")
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	for _, b := range raw {
		if b != 0 {
			t.Fatal("request buffer not cleared on close")
		}
	}
	if n, err := body.Read(read); n != 0 || err != io.EOF {
		t.Fatal("closed request body remained readable")
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestBodyConcurrentReadClose(t *testing.T) {
	raw := make([]byte, 65536)
	for i := range raw {
		raw[i] = 'x'
	}
	body := newTokenRequestBody(raw)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			buffer := make([]byte, 1024)
			for {
				if _, err := body.Read(buffer); err != nil {
					return
				}
			}
		})
	}
	group.Go(func() { _ = body.Close() })
	group.Wait()
	_ = body.Close()
	for _, b := range raw {
		if b != 0 {
			t.Fatal("concurrent request close did not clear ownership")
		}
	}
}
