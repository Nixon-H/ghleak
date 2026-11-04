package internal

import (
	"encoding/json"
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

// ── Provider presets, endpoints, and cache mechanics ───────────────

func TestNormalizeChatEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://api.openai.com/v1":                  "https://api.openai.com/v1/chat/completions",
		"https://api.openai.com/v1/":                 "https://api.openai.com/v1/chat/completions",
		"https://api.openai.com/v1/chat/completions": "https://api.openai.com/v1/chat/completions",
		"https://opencode.ai/inference/go/openai/v1": "https://opencode.ai/inference/go/openai/v1/chat/completions",
		"": "",
	}
	for in, want := range cases {
		if got := normalizeChatEndpoint(in); got != want {
			t.Errorf("normalizeChatEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProviderPresets(t *testing.T) {
	openai := BuildLLMBackend("openai", "", "sk-test", "")
	ob, ok := openai.(*OpenAIBackend)
	if !ok {
		t.Fatalf("openai: expected *OpenAIBackend, got %T", openai)
	}
	if ob.Endpoint != LLMProviderPresets["openai"].Endpoint || !ob.PromptCacheKey {
		t.Errorf("openai preset wrong: endpoint=%q cacheKey=%v", ob.Endpoint, ob.PromptCacheKey)
	}

	anthropic := BuildLLMBackend("anthropic", "", "sk-ant-test", "")
	ab, ok := anthropic.(*AnthropicBackend)
	if !ok || ab.endpoint() != LLMProviderPresets["anthropic"].Endpoint {
		t.Fatalf("anthropic preset wrong: %T %v", anthropic, ab)
	}

	if gemini := BuildLLMBackend("gemini", "", "AIza-test", ""); gemini == nil {
		t.Error("gemini preset should build with a key")
	}

	goB := BuildLLMBackend("opencode-go", "", "oc_sk_test", "")
	cg, ok := goB.(*OpenAIBackend)
	if !ok {
		t.Fatalf("opencode-go: expected *OpenAIBackend, got %T", goB)
	}
	if cg.Endpoint != LLMProviderPresets["opencode-go"].Endpoint {
		t.Errorf("opencode-go endpoint = %q", cg.Endpoint)
	}
	if cg.ExtraHeaders["x-opencode-session"] == "" {
		t.Error("opencode-go must send x-opencode-session for cache affinity")
	}
	if cg.PromptCacheKey {
		t.Error("opencode-go should not send prompt_cache_key (gateway may reject)")
	}

	if alias := BuildLLMBackend("opencode", "https://gateway.example/v1", "", ""); alias == nil {
		t.Error("opencode alias should resolve to opencode-go")
	}
	if custom := BuildLLMBackend("custom", "", "k", ""); custom != nil {
		t.Error("custom without endpoint should be rejected")
	}
}

func TestOpenAICacheKeyAndUsage(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"true"}}],` +
			`"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":90}}}`))
	}))
	defer srv.Close()

	b := NewOpenAICompatibleBackend("openai", srv.URL, "sk-test", "gpt-test", "sess-1")
	b.PromptCacheKey = true
	if _, err := b.Classify("remove leaked api key"); err != nil {
		t.Fatalf("classify: %v", err)
	}
	if captured["prompt_cache_key"] != "ghleak-gpt-test" {
		t.Errorf("prompt_cache_key = %v", captured["prompt_cache_key"])
	}
	msgs, _ := captured["messages"].([]any)
	if len(msgs) < 2 {
		t.Fatalf("expected system+user messages, got %v", msgs)
	}
	if m0, _ := msgs[0].(map[string]any); m0["role"] != "system" {
		t.Errorf("first message should be the stable system prompt, got %v", m0)
	}
	in, cached := b.CacheStats()
	if in != 100 || cached != 90 {
		t.Errorf("cache stats = (%d,%d), want (100,90)", in, cached)
	}
}

func TestOpenCodeGoSessionHeaderAndNoCacheKey(t *testing.T) {
	var session string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session = r.Header.Get("x-opencode-session")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"false"}}]}`))
	}))
	defer srv.Close()

	b := BuildLLMBackend("opencode-go", srv.URL, "oc_sk_test", "")
	if _, err := b.Classify("update readme"); err != nil {
		t.Fatalf("classify: %v", err)
	}
	if session == "" {
		t.Error("x-opencode-session header missing")
	}
	if _, present := body["prompt_cache_key"]; present {
		t.Error("prompt_cache_key must not be sent to OpenCode Go")
	}
}

func TestAnthropicCacheControlAndUsage(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"content":[{"text":"true"}],` +
			`"usage":{"input_tokens":100,"cache_read_input_tokens":900,"cache_creation_input_tokens":0}}`))
	}))
	defer srv.Close()

	b := NewAnthropicBackend("sk-ant-test", "claude-test")
	b.Endpoint = srv.URL
	if _, err := b.Classify("rotate database password"); err != nil {
		t.Fatalf("classify: %v", err)
	}

	system, _ := body["system"].([]any)
	if len(system) == 0 {
		t.Fatal("expected a system block")
	}
	sys0, _ := system[0].(map[string]any)
	cc, _ := sys0["cache_control"].(map[string]any)
	if cc["type"] != "ephemeral" {
		t.Errorf("system block must carry cache_control ephemeral, got %v", sys0)
	}
	msgs, _ := body["messages"].([]any)
	if m0, _ := msgs[0].(map[string]any); m0["role"] != "user" {
		t.Errorf("messages must be user-only, got %v", msgs)
	}

	in, cached := b.CacheStats()
	if in != 1000 || cached != 900 {
		t.Errorf("cache stats = (%d,%d), want (1000,900)", in, cached)
	}
}
