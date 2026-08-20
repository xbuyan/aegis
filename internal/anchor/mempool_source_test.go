package anchor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMempoolSource_BlockHeader_ParsesAndReversesMerkleRoot(t *testing.T) {
	const blockHash = "0000000000000000000000000000000000000000000000000000000000000001"
	// Display (reversed) order merkle root, as mempool.space's JSON returns.
	const displayMerkleRoot = "0101010101010101010101010101010101010101010101010101010101010101"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/block-height/850000":
			fmt.Fprint(w, blockHash)
		case strings.HasPrefix(r.URL.Path, "/block/"):
			fmt.Fprintf(w, `{"merkle_root":"%s","timestamp":1700000000}`, displayMerkleRoot)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	src := &MempoolSource{BaseURL: server.URL}
	header, err := src.BlockHeader(context.Background(), 850000)
	if err != nil {
		t.Fatalf("BlockHeader: %v", err)
	}

	displayBytes, err := hexToBytes32(displayMerkleRoot)
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	wantInternal := reverseBytes32(displayBytes)

	if header.MerkleRoot != wantInternal {
		t.Errorf("MerkleRoot = %x, want %x (reversed from display order %s)", header.MerkleRoot, wantInternal, displayMerkleRoot)
	}
	if header.Time.Unix() != 1700000000 {
		t.Errorf("Time.Unix() = %d, want 1700000000", header.Time.Unix())
	}
	if header.Height != 850000 {
		t.Errorf("Height = %d, want 850000", header.Height)
	}
}

func TestMempoolSource_BlockHeightNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	src := &MempoolSource{BaseURL: server.URL}
	_, err := src.BlockHeader(context.Background(), 999999999)
	if err == nil {
		t.Fatal("BlockHeader for a nonexistent height: want error, got nil")
	}
}

func TestMempoolSource_MalformedBlockHashRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not-a-valid-hash")
	}))
	defer server.Close()

	src := &MempoolSource{BaseURL: server.URL}
	_, err := src.BlockHeader(context.Background(), 1)
	if err == nil {
		t.Fatal("BlockHeader with a malformed block hash response: want error, got nil")
	}
}

func TestMempoolSource_DefaultBaseURL(t *testing.T) {
	src := &MempoolSource{}
	if src.baseURL() != "https://mempool.space/api" {
		t.Errorf("default baseURL = %q, want https://mempool.space/api", src.baseURL())
	}

	trimmed := &MempoolSource{BaseURL: "https://example.com/api/"}
	if trimmed.baseURL() != "https://example.com/api" {
		t.Errorf("baseURL with trailing slash = %q, want trimmed", trimmed.baseURL())
	}
}
