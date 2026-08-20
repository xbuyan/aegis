package anchor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBitcoinRPCSource_BlockHeader_ParsesAndReversesMerkleRoot(t *testing.T) {
	const blockHash = "0000000000000000000abcdef1234567890abcdef1234567890abcdef12345"
	const displayMerkleRoot = "abababababababababababababababababababababababababababababababab"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("bad request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "getblockhash":
			fmt.Fprintf(w, `{"result":"%s","error":null}`, blockHash)
		case "getblockheader":
			fmt.Fprintf(w, `{"result":{"merkleroot":"%s","time":1700000000},"error":null}`, displayMerkleRoot)
		default:
			t.Errorf("unexpected RPC method: %s", req.Method)
		}
	}))
	defer server.Close()

	src := &BitcoinRPCSource{URL: server.URL, User: "rpcuser", Password: "rpcpass"}
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
		t.Errorf("MerkleRoot = %x, want %x", header.MerkleRoot, wantInternal)
	}
	if header.Time.Unix() != 1700000000 {
		t.Errorf("Time.Unix() = %d, want 1700000000", header.Time.Unix())
	}
}

func TestBitcoinRPCSource_RPCErrorPropagates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"result":null,"error":{"code":-8,"message":"Block height out of range"}}`)
	}))
	defer server.Close()

	src := &BitcoinRPCSource{URL: server.URL}
	_, err := src.BlockHeader(context.Background(), 99999999)
	if err == nil {
		t.Fatal("BlockHeader with an RPC error response: want error, got nil")
	}
}

func TestBitcoinRPCSource_SendsBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	var gotOK bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		fmt.Fprint(w, `{"result":"deadbeef","error":null}`)
	}))
	defer server.Close()

	src := &BitcoinRPCSource{URL: server.URL, User: "alice", Password: "s3cret"}
	_ = src.call(context.Background(), "getblockhash", []interface{}{1}, new(string))

	if !gotOK {
		t.Fatal("request did not include Basic Auth")
	}
	if gotUser != "alice" || gotPass != "s3cret" {
		t.Errorf("got auth (%q, %q), want (alice, s3cret)", gotUser, gotPass)
	}
}

func TestBitcoinRPCSource_NoAuthWhenUserEmpty(t *testing.T) {
	var gotOK bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, gotOK = r.BasicAuth()
		fmt.Fprint(w, `{"result":"deadbeef","error":null}`)
	}))
	defer server.Close()

	src := &BitcoinRPCSource{URL: server.URL}
	_ = src.call(context.Background(), "getblockhash", []interface{}{1}, new(string))

	if gotOK {
		t.Error("request included Basic Auth despite no User configured")
	}
}
