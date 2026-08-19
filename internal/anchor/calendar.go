package anchor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrCommitmentNotFound is returned by Calendar.Upgrade when the calendar
// doesn't (yet) have an attestation for the given digest — the timestamp
// is still pending, not an error condition to alarm over.
var ErrCommitmentNotFound = errors.New("anchor: calendar has no commitment for this digest yet")

// maxCalendarResponseBytes bounds how much of a calendar's response body
// gets read, mirroring the reference client's own 10000-byte limit —
// defends against a misbehaving or malicious server sending unbounded data.
const maxCalendarResponseBytes = 10000

// Calendar is an OpenTimestamps calendar server client. It implements
// only the two operations Aegis needs: submitting a digest, and later
// checking whether that digest has been upgraded to a Bitcoin attestation.
type Calendar struct {
	// URL is the calendar's base URL, e.g. "https://a.pool.opentimestamps.org".
	URL string
	// HTTPClient is used for requests. If nil, a client with a 30s
	// timeout is used.
	HTTPClient *http.Client
}

func (c *Calendar) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Submit posts digest (expected to be a 32-byte SHA-256 hash) to the
// calendar and returns the resulting Timestamp tree, rooted at digest.
// Immediately after submission this will normally contain a single
// PendingAttestation for this same calendar's URI — call Upgrade later to
// check whether it has become a Bitcoin attestation.
func (c *Calendar) Submit(ctx context.Context, digest []byte) (*Timestamp, error) {
	target, err := url.JoinPath(c.URL, "digest")
	if err != nil {
		return nil, fmt.Errorf("anchor: build submit URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(digest)))
	if err != nil {
		return nil, fmt.Errorf("anchor: build submit request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", "aegis-anchor/0.1")
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("anchor: submit to calendar %s: %w", c.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: calendar %s returned status %d on submit", c.URL, resp.StatusCode)
	}

	body, err := readLimited(resp.Body, maxCalendarResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("anchor: read submit response from %s: %w", c.URL, err)
	}

	ts, err := DeserializeTimestamp(body, digest)
	if err != nil {
		return nil, fmt.Errorf("anchor: parse submit response from %s: %w", c.URL, err)
	}
	return ts, nil
}

// Upgrade asks the calendar for the current state of a previously
// submitted digest. Returns ErrCommitmentNotFound if the calendar
// responds 404 (nothing to report yet — try again later, this is not
// itself an error to surface as a failure).
func (c *Calendar) Upgrade(ctx context.Context, digest []byte) (*Timestamp, error) {
	target, err := url.JoinPath(c.URL, "timestamp", hex.EncodeToString(digest))
	if err != nil {
		return nil, fmt.Errorf("anchor: build upgrade URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("anchor: build upgrade request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", "aegis-anchor/0.1")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("anchor: upgrade check against calendar %s: %w", c.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrCommitmentNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchor: calendar %s returned status %d on upgrade", c.URL, resp.StatusCode)
	}

	body, err := readLimited(resp.Body, maxCalendarResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("anchor: read upgrade response from %s: %w", c.URL, err)
	}

	ts, err := DeserializeTimestamp(body, digest)
	if err != nil {
		return nil, fmt.Errorf("anchor: parse upgrade response from %s: %w", c.URL, err)
	}
	return ts, nil
}

// readLimited reads up to maxBytes from r and errors if more data was
// available, rather than silently truncating a response that might be
// larger than expected.
func readLimited(r io.Reader, maxBytes int) ([]byte, error) {
	limited := io.LimitReader(r, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("response exceeded %d byte limit", maxBytes)
	}
	return data, nil
}
