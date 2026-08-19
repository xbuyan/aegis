package anchor

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCalendar_Submit_ParsesPendingResponse(t *testing.T) {
	digest := sha256.Sum256([]byte("evidence content"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/digest" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(digest[:]) {
			t.Errorf("submitted body = %x, want %x", body, digest)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(append([]byte{0x00}, pendingAttestationBytes("https://example.calendar")...))
	}))
	defer server.Close()

	cal := &Calendar{URL: server.URL}
	ts, err := cal.Submit(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(ts.Attestations) != 1 {
		t.Fatalf("got %d attestations, want 1", len(ts.Attestations))
	}
	pa, ok := ts.Attestations[0].(PendingAttestation)
	if !ok || pa.URI != "https://example.calendar" {
		t.Errorf("attestation = %v, want PendingAttestation(https://example.calendar)", ts.Attestations[0])
	}
}

func TestCalendar_Submit_NonOKStatusErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cal := &Calendar{URL: server.URL}
	_, err := cal.Submit(context.Background(), make([]byte, 32))
	if err == nil {
		t.Fatal("Submit against a 500 response: want error, got nil")
	}
}

func TestCalendar_Upgrade_ParsesBitcoinAttestation(t *testing.T) {
	digest := sha256.Sum256([]byte("evidence content"))
	heightPayload := varUintBytes(850000)

	var attBytes []byte
	attBytes = append(attBytes, attestationTagBitcoin[:]...)
	attBytes = append(attBytes, byte(len(heightPayload)))
	attBytes = append(attBytes, heightPayload...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/timestamp/" + hexEncode(digest[:])
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			t.Errorf("unexpected request: %s %s, want GET %s", r.Method, r.URL.Path, wantPath)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(append([]byte{0x00}, attBytes...))
	}))
	defer server.Close()

	cal := &Calendar{URL: server.URL}
	ts, err := cal.Upgrade(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if len(ts.Attestations) != 1 {
		t.Fatalf("got %d attestations, want 1", len(ts.Attestations))
	}
	ba, ok := ts.Attestations[0].(BitcoinBlockHeaderAttestation)
	if !ok || ba.Height != 850000 {
		t.Errorf("attestation = %v, want BitcoinBlockHeaderAttestation(850000)", ts.Attestations[0])
	}
}

func TestCalendar_Upgrade_NotFoundReturnsSentinelError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Pending confirmation in Bitcoin blockchain"))
	}))
	defer server.Close()

	cal := &Calendar{URL: server.URL}
	_, err := cal.Upgrade(context.Background(), make([]byte, 32))
	if !errors.Is(err, ErrCommitmentNotFound) {
		t.Errorf("Upgrade error = %v, want ErrCommitmentNotFound", err)
	}
}

func TestCalendar_Submit_OversizedResponseRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		huge := make([]byte, maxCalendarResponseBytes+1)
		w.Write(huge)
	}))
	defer server.Close()

	cal := &Calendar{URL: server.URL}
	_, err := cal.Submit(context.Background(), make([]byte, 32))
	if err == nil {
		t.Fatal("Submit with oversized response: want error, got nil")
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
