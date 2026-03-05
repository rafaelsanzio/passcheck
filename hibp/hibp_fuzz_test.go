package hibp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzCheckHash(f *testing.F) {
	f.Add("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
	f.Add("short")
	f.Add("nothexstringnothexstringnothexstringnot1")

	// Set up a dummy server to avoid hitting the actual API during fuzzing
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0000000000000000000000000000000000000:1\n"))
	}))
	defer server.Close()

	c := NewClient()
	c.BaseURL = server.URL
	c.HTTPClient = server.Client()

	f.Fuzz(func(t *testing.T, hash string) {
		_, _, _ = c.CheckHashContext(context.Background(), hash)
	})
}
