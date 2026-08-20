package anchor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MempoolSource fetches block headers from a mempool.space-compatible
// REST API. This is convenient — no setup, works immediately — but it
// means trusting that API not to lie about a block's merkle root. Aegis
// also supports BitcoinRPCSource for users who'd rather verify against
// their own node; MempoolSource exists for the common case (a journalist
// who isn't going to run a full node) where convenience matters more than
// eliminating this one specific trust dependency.
type MempoolSource struct {
	// BaseURL defaults to "https://mempool.space/api" if empty.
	BaseURL string
	// HTTPClient defaults to a client with a 15s timeout if nil.
	HTTPClient *http.Client
}

func (m *MempoolSource) baseURL() string {
	if m.BaseURL != "" {
		return strings.TrimRight(m.BaseURL, "/")
	}
	return "https://mempool.space/api"
}

func (m *MempoolSource) httpClient() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

type mempoolBlockResponse struct {
	MerkleRoot string `json:"merkle_root"`
	Timestamp  int64  `json:"timestamp"`
}

// BlockHeader implements BlockHeaderSource.
func (m *MempoolSource) BlockHeader(ctx context.Context, height uint64) (*BlockHeader, error) {
	blockHash, err := m.blockHashAtHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	target := fmt.Sprintf("%s/block/%s", m.baseURL(), blockHash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("anchor: build mempool.space block request: %w", err)
	}

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("anchor: fetch block from mempool.space: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: mempool.space returned status %d for block %s", resp.StatusCode, blockHash)
	}

	var parsed mempoolBlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("anchor: decode mempool.space block response: %w", err)
	}

	displayOrder, err := hexToBytes32(parsed.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("anchor: parse merkle_root from mempool.space: %w", err)
	}

	return &BlockHeader{
		Height:     height,
		MerkleRoot: reverseBytes32(displayOrder), // API returns display (reversed) order
		Time:       time.Unix(parsed.Timestamp, 0).UTC(),
	}, nil
}

func (m *MempoolSource) blockHashAtHeight(ctx context.Context, height uint64) (string, error) {
	target := fmt.Sprintf("%s/block-height/%d", m.baseURL(), height)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("anchor: build mempool.space block-height request: %w", err)
	}

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("anchor: fetch block hash from mempool.space: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anchor: mempool.space returned status %d for height %d", resp.StatusCode, height)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", fmt.Errorf("anchor: read block-height response: %w", err)
	}
	hash := strings.TrimSpace(string(body))
	if len(hash) != 64 {
		return "", fmt.Errorf("anchor: unexpected block hash format from mempool.space: %q", hash)
	}
	return hash, nil
}

// hexToBytes32 parses a 64-character hex string into a fixed 32-byte array.
func hexToBytes32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
