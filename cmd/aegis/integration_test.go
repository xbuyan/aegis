package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This test builds and runs the actual `aegis` binary as a subprocess —
// exercising the real CLI end to end, not just the internal packages in
// isolation — against a mock calendar server standing in for a real one.
func TestCLI_CaptureThenVerify_EndToEnd(t *testing.T) {
	// A minimal fake calendar: always responds with a PendingAttestation
	// pointing at itself. Good enough to prove capture -> log -> anchor
	// store -> verify all wire together correctly; it does not exercise
	// a real Bitcoin confirmation (that needs a real calendar and real
	// time to pass — see the live tests already run against production
	// infrastructure for that).
	calendar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/digest" {
			w.WriteHeader(http.StatusOK)
			// 0x00 + PendingAttestation TAG + varbytes(varbytes(uri))
			uri := "https://fake.calendar.test"
			inner := append([]byte{byte(len(uri))}, []byte(uri)...)
			resp := append([]byte{0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}, byte(len(inner)))
			resp = append(resp, inner...)
			w.Write(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer calendar.Close()

	binPath := buildAegisBinary(t)

	workDir := t.TempDir()
	testFile := filepath.Join(workDir, "evidence.txt")
	if err := os.WriteFile(testFile, []byte("this is real evidence content"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	logPath := filepath.Join(workDir, "log.jsonl")
	evidenceDir := filepath.Join(workDir, "evidence-store")
	anchorsDir := filepath.Join(workDir, "anchors-store")

	// --- capture ---
	captureOut, err := runBinary(binPath,
		"capture",
		"-log", logPath,
		"-evidence", evidenceDir,
		"-anchors", anchorsDir,
		"-calendar", calendar.URL,
		testFile,
	)
	if err != nil {
		t.Fatalf("capture failed: %v\noutput:\n%s", err, captureOut)
	}
	if !strings.Contains(captureOut, "Content hash:") {
		t.Errorf("capture output missing content hash, got:\n%s", captureOut)
	}
	if !strings.Contains(captureOut, "Logged: index 0") {
		t.Errorf("capture output missing log confirmation, got:\n%s", captureOut)
	}
	if !strings.Contains(captureOut, "Submitted for anchoring") {
		t.Errorf("capture output missing anchor submission confirmation, got:\n%s", captureOut)
	}

	// --- verify (same file, should all pass) ---
	verifyOut, err := runBinary(binPath,
		"verify",
		"-log", logPath,
		"-evidence", evidenceDir,
		"-anchors", anchorsDir,
		testFile,
	)
	if err != nil {
		t.Fatalf("verify failed: %v\noutput:\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "OK: content matches a captured record") {
		t.Errorf("verify output missing content match confirmation, got:\n%s", verifyOut)
	}
	if !strings.Contains(verifyOut, "OK: log chain integrity verified") {
		t.Errorf("verify output missing log integrity confirmation, got:\n%s", verifyOut)
	}
	if !strings.Contains(verifyOut, "OK: found log entry (index 0)") {
		t.Errorf("verify output missing log entry confirmation, got:\n%s", verifyOut)
	}
	if !strings.Contains(verifyOut, "Anchor still pending") {
		t.Errorf("verify output should report pending anchor (mock calendar never confirms), got:\n%s", verifyOut)
	}

	// --- verify a tampered copy of the file (should fail content match) ---
	tamperedFile := filepath.Join(workDir, "tampered.txt")
	if err := os.WriteFile(tamperedFile, []byte("this is DIFFERENT evidence content"), 0o600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}
	tamperedOut, err := runBinary(binPath,
		"verify",
		"-log", logPath,
		"-evidence", evidenceDir,
		"-anchors", anchorsDir,
		tamperedFile,
	)
	if err != nil {
		t.Fatalf("verify (tampered) failed unexpectedly: %v\noutput:\n%s", err, tamperedOut)
	}
	if !strings.Contains(tamperedOut, "FAIL: no evidence record found") {
		t.Errorf("verify of never-captured content should report FAIL, got:\n%s", tamperedOut)
	}
}

func TestCLI_Verify_TamperedLogDetected(t *testing.T) {
	calendar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e, 0x02, 0x01, 'x'})
	}))
	defer calendar.Close()

	binPath := buildAegisBinary(t)

	workDir := t.TempDir()
	testFile := filepath.Join(workDir, "evidence.txt")
	if err := os.WriteFile(testFile, []byte("evidence for tamper test"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	logPath := filepath.Join(workDir, "log.jsonl")
	evidenceDir := filepath.Join(workDir, "evidence-store")
	anchorsDir := filepath.Join(workDir, "anchors-store")

	if _, err := runBinary(binPath, "capture",
		"-log", logPath, "-evidence", evidenceDir, "-anchors", anchorsDir, "-calendar", calendar.URL, testFile); err != nil {
		t.Fatalf("capture failed: %v", err)
	}

	// Tamper with the log file directly on disk.
	original, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	tampered := bytes.Replace(original, []byte("index"), []byte("index"), 1) // no-op placeholder
	_ = tampered
	corrupted := append([]byte{}, original...)
	// Flip a byte in the middle of the JSON line to corrupt chain_hash's value.
	if len(corrupted) > 20 {
		corrupted[20] ^= 0xFF
	}
	if err := os.WriteFile(logPath, corrupted, 0o600); err != nil {
		t.Fatalf("write corrupted log: %v", err)
	}

	verifyOut, err := runBinary(binPath, "verify",
		"-log", logPath, "-evidence", evidenceDir, "-anchors", anchorsDir, testFile)
	if err != nil {
		t.Fatalf("verify failed unexpectedly: %v\noutput:\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "FAIL:") {
		t.Errorf("verify of a tampered log should report a FAIL somewhere, got:\n%s", verifyOut)
	}
}

func buildAegisBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "aegis-test-bin")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = mustGetwd(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build aegis binary: %v\n%s", err, out)
	}
	return binPath
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	return wd
}

func runBinary(binPath string, args ...string) (string, error) {
	cmd := exec.Command(binPath, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err != nil {
		return buf.String(), fmt.Errorf("%w", err)
	}
	return buf.String(), nil
}
