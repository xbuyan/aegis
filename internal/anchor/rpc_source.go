package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// BitcoinRPCSource fetches block headers from a Bitcoin Core node's own
// JSON-RPC interface (getblockhash + getblockheader). This is the
// trust-minimized option: verification depends on nothing but Bitcoin
// consensus rules as your own node enforces them, not on any third
// party's word. Costs real setup (a pruned node is enough, but it's still
// a node) — see MempoolSource for the zero-setup alternative.
type BitcoinRPCSource struct {
	// URL is the node's RPC endpoint, e.g. "http://127.0.0.1:8332".
	URL      string
	User     string
	Password string
	// HTTPClient defaults to a client with a 15s timeout if nil.
	HTTPClient *http.Client
}

func (b *BitcoinRPCSource) httpClient() *http.Client {
	if b.HTTPClient != nil {
		return b.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func (b *BitcoinRPCSource) call(ctx context.Context, method string, params []interface{}, out interface{}) error {
	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "1.0",
		ID:      "aegis-anchor",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("anchor: marshal RPC request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("anchor: build RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if b.User != "" {
		req.SetBasicAuth(b.User, b.Password)
	}

	resp, err := b.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("anchor: call Bitcoin RPC method %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		// Bitcoin Core returns 500 with a JSON-RPC error body for
		// application-level errors (e.g. block not found), so only
		// reject status codes that indicate something else went wrong
		// (auth failure, wrong endpoint, etc).
		return fmt.Errorf("anchor: Bitcoin RPC returned status %d for method %s", resp.StatusCode, method)
	}

	var parsed rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("anchor: decode RPC response for method %s: %w", method, err)
	}
	if parsed.Error != nil {
		return fmt.Errorf("anchor: Bitcoin RPC error on %s: %s (code %d)", method, parsed.Error.Message, parsed.Error.Code)
	}
	if err := json.Unmarshal(parsed.Result, out); err != nil {
		return fmt.Errorf("anchor: unmarshal RPC result for method %s: %w", method, err)
	}
	return nil
}

type rpcBlockHeaderResult struct {
	MerkleRoot string `json:"merkleroot"`
	Time       int64  `json:"time"`
}

// BlockHeader implements BlockHeaderSource.
func (b *BitcoinRPCSource) BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error) {
	var blockHash string
	if err := b.call(ctx, "getblockhash", []interface{}{height}, &blockHash); err != nil {
		return nil, fmt.Errorf("anchor: getblockhash(%d): %w", height, err)
	}

	var header rpcBlockHeaderResult
	if err := b.call(ctx, "getblockheader", []interface{}{blockHash}, &header); err != nil {
		return nil, fmt.Errorf("anchor: getblockheader(%s): %w", blockHash, err)
	}

	displayOrder, err := hexToBytes32(header.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("anchor: parse merkleroot from getblockheader: %w", err)
	}

	return &BlockHeader{
		Height:     height,
		MerkleRoot: reverseBytes32(displayOrder), // RPC returns display (reversed) order, same as mempool.space
		Time:       time.Unix(header.Time, 0).UTC(),
	}, nil
}
