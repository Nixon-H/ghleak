package internal

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The LLM backends must survive provider rate limits: retry 429/5xx with
// backoff instead of surfacing a failure (or worse, a false "clean").
// Endpoint overrides make the backends testable against httptest servers.

func TestGeminiRetries429(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"true"}]}}]}`))
	}))
	defer srv.Close()

	b := NewGeminiBackend("test-key", "gemini-test")
	b.Endpoint = srv.URL
	result, err := b.Classify("remove leaked api key")
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if result != Suspicious {
		t.Errorf("expected Suspicious, got %v", result)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 calls (429 then 200), got %d", got)
	}
}

func TestAnthropicRetries500(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"text":"true"}]}`))
	}))
	defer srv.Close()

	b := NewAnthropicBackend("test-key", "claude-test")
	b.Endpoint = srv.URL
	result, err := b.Classify("rotate database password")
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if result != Suspicious {
		t.Errorf("expected Suspicious, got %v", result)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 calls (500 then 200), got %d", got)
	}
}

func TestAnthropicNonRetryableErrorSurfaces(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid model"}`))
	}))
	defer srv.Close()

	b := NewAnthropicBackend("test-key", "claude-test")
	b.Endpoint = srv.URL
	_, err := b.Classify("remove leaked api key")
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("400 must not be retried, got %d calls", got)
	}
}

func TestAnthropicBatchRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"text":"{\"0\":true,\"1\":false}"}]}`))
	}))
	defer srv.Close()

	b := NewAnthropicBackend("test-key", "claude-test")
	b.Endpoint = srv.URL
	out, err := b.ClassifyBatch([]string{"remove leaked key", "update readme"})
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if out[0] != Suspicious || out[1] != Clean {
		t.Errorf("unexpected batch result: %+v", out)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 calls, got %d", got)
	}
}
