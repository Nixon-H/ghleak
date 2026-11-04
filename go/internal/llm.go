package internal

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LLMBackend is the interface for AI fallback classification.
//
// All backends report prompt-cache usage so callers can see the real hit
// rate (cached input tokens / total input tokens) instead of guessing.
type LLMBackend interface {
	Classify(message string) (Classification, error)
	ClassifyBatch(messages []string) (map[int]Classification, error)
	CacheStats() (input, cached int64)
}

// cacheCounters accumulates provider-reported usage across calls.
type cacheCounters struct {
	mu     sync.Mutex
	input  int64
	cached int64
}

func (c *cacheCounters) add(input, cached int) {
	if input <= 0 && cached <= 0 {
		return
	}
	c.mu.Lock()
	c.input += int64(input)
	c.cached += int64(cached)
	c.mu.Unlock()
}

func (c *cacheCounters) get() (int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.input, c.cached
}

// newSessionID is the cache-affinity identifier. Stable for the process
// lifetime; override with GHLEAK_LLM_SESSION to share a cache across runs.
func newSessionID() string {
	if v := strings.TrimSpace(os.Getenv("GHLEAK_LLM_SESSION")); v != "" {
		return v
	}
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("ghleak-%d", time.Now().UnixNano())
	}
	return "ghleak-" + hex.EncodeToString(b)
}

// normalizeChatEndpoint accepts either a base URL ("…/v1") or a full path
// ("…/chat/completions") and returns the full chat-completions URL.
func normalizeChatEndpoint(ep string) string {
	ep = strings.TrimRight(strings.TrimSpace(ep), "/")
	if ep == "" {
		return ep
	}
	if strings.HasSuffix(ep, "/chat/completions") {
		return ep
	}
	return ep + "/chat/completions"
}

// sleepBackoff sleeps with exponential backoff plus jitter, honoring the
// server's Retry-After header when present. Shared by LLM and API clients.
func sleepBackoff(attempt int, retryAfter string) {
	delay := float64(time.Second) * math.Min(math.Pow(2, float64(attempt)), 60)
	delay *= 0.5 + mathrand.Float64() // jitter: 50%-150%
	if retryAfter != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && secs > 0 {
			if float64(secs)*float64(time.Second) > delay {
				delay = float64(secs) * float64(time.Second)
			}
		}
	}
	time.Sleep(time.Duration(delay))
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// doWithRetry executes an HTTP request with retries for 429/5xx/transport
// errors, honoring Retry-After.
func doWithRetry(client *http.Client, method, urlStr string, headers map[string]string,
	body []byte, attempts int) ([]byte, int, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, urlStr, rdr)
		if err != nil {
			return nil, 0, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			sleepBackoff(i, "")
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(data), 200))
			sleepBackoff(i, resp.Header.Get("Retry-After"))
			continue
		}
		return data, resp.StatusCode, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("request failed after retries")
	}
	return nil, 0, lastErr
}

// ── OpenAI-compatible backend (OpenAI, OpenCode Go, custom gateways) ──

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model          string          `json:"model"`
	Messages       []openAIMessage `json:"messages"`
	Temperature    float64         `json:"temperature"`
	MaxTokens      int             `json:"max_tokens"`
	PromptCacheKey string          `json:"prompt_cache_key,omitempty"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIUsage struct {
	PromptTokens       int `json:"prompt_tokens"`
	PromptTokensDetail struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

type OpenAIBackend struct {
	Provider       string
	Endpoint       string
	APIKey         string
	Model          string
	SessionID      string
	PromptCacheKey bool              // OpenAI: send prompt_cache_key for cache affinity
	ExtraHeaders   map[string]string // e.g. x-opencode-session
	Client         *http.Client
	stats          cacheCounters
}

// NewOpenAIBackend keeps the historical signature (custom gateway).
func NewOpenAIBackend(endpoint, apiKey, model string) *OpenAIBackend {
	return NewOpenAICompatibleBackend("openai-compatible", endpoint, apiKey, model, "")
}

// NewOpenAICompatibleBackend builds a chat-completions backend.
func NewOpenAICompatibleBackend(provider, endpoint, apiKey, model, session string) *OpenAIBackend {
	if provider == "" {
		provider = "openai-compatible"
	}
	if session == "" {
		session = newSessionID()
	}
	return &OpenAIBackend{
		Provider:  provider,
		Endpoint:  normalizeChatEndpoint(endpoint),
		APIKey:    apiKey,
		Model:     model,
		SessionID: session,
		Client:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (b *OpenAIBackend) CacheStats() (int64, int64) { return b.stats.get() }

func (b *OpenAIBackend) doRequest(system, user string, maxTokens int) (string, error) {
	req := openAIRequest{
		Model: b.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0.0,
		MaxTokens:   maxTokens,
	}
	// OpenAI routes cache shards by this key; a stable value keeps every
	// call of one model on the same warm shard.
	if b.PromptCacheKey {
		req.PromptCacheKey = "ghleak-" + b.Model
	}

	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("llm marshal: %w", err)
	}

	headers := map[string]string{"Content-Type": "application/json"}
	if b.APIKey != "" {
		headers["Authorization"] = "Bearer " + b.APIKey
	}
	for k, v := range b.ExtraHeaders {
		headers[k] = v
	}

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		respData, status, err := doWithRetryOnce(b.Client, b.Endpoint, headers, data)
		if err != nil {
			lastErr = fmt.Errorf("llm do: %w", err)
			sleepBackoff(attempt, "")
			continue
		}
		if status == 429 || status >= 500 {
			lastErr = fmt.Errorf("llm HTTP %d: %s", status, truncateStr(string(respData), 200))
			sleepBackoff(attempt, "")
			continue
		}
		if status != 200 {
			return "", fmt.Errorf("llm HTTP %d: %s", status, truncateStr(string(respData), 200))
		}
		var openAIResp openAIResponse
		if err := json.Unmarshal(respData, &openAIResp); err != nil {
			return "", fmt.Errorf("llm decode: %w", err)
		}
		if len(openAIResp.Choices) == 0 {
			return "", fmt.Errorf("llm no choices")
		}
		b.stats.add(openAIResp.Usage.PromptTokens, openAIResp.Usage.PromptTokensDetail.CachedTokens)
		return strings.TrimSpace(openAIResp.Choices[0].Message.Content), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("llm request failed after retries")
	}
	return "", lastErr
}

// doWithRetryOnce performs a single attempt; retry loop lives in doRequest so
// the body can be replayed safely.
func doWithRetryOnce(client *http.Client, urlStr string, headers map[string]string,
	body []byte) ([]byte, int, error) {
	req, err := http.NewRequest("POST", urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return data, resp.StatusCode, nil
}

func (b *OpenAIBackend) classifyOne(msg string) (Classification, error) {
	user := strings.Replace(OneShotUserPrompt, "{commit_message}", msg, 1)
	text, err := b.doRequest(OneShotSystemPrompt, user, 64)
	if err != nil {
		return Clean, err
	}
	if strings.HasPrefix(strings.ToLower(text), "true") {
		return Suspicious, nil
	}
	return Clean, nil
}

func (b *OpenAIBackend) Classify(msg string) (Classification, error) {
	return b.classifyOne(msg)
}

func (b *OpenAIBackend) ClassifyBatch(msgs []string) (map[int]Classification, error) {
	var parts []string
	for i, m := range msgs {
		parts = append(parts, fmt.Sprintf("[%d] %s", i, m))
	}
	user := strings.Replace(BatchUserPrompt, "{messages}", strings.Join(parts, "\n---\n"), 1)
	text, err := b.doRequest(BatchSystemPrompt, user, 1024)
	if err != nil {
		return nil, err
	}
	return parseBatchResponse(text)
}

// ── Gemini backend ─────────────────────────────────────────────────

type GeminiBackend struct {
	APIKey    string
	Model     string
	Endpoint  string // override for tests/self-hosted gateways
	SessionID string
	Client    *http.Client
	stats     cacheCounters
}

func NewGeminiBackend(apiKey, model string) *GeminiBackend {
	if model == "" {
		model = DefaultLLMModel
	}
	return &GeminiBackend{
		APIKey:    apiKey,
		Model:     model,
		SessionID: newSessionID(),
		Client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (b *GeminiBackend) CacheStats() (int64, int64) { return b.stats.get() }

func (b *GeminiBackend) endpoint() string {
	if b.Endpoint != "" {
		return b.Endpoint
	}
	return fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		b.Model, b.APIKey)
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiRequest struct {
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
	Contents          []geminiContent `json:"contents"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

type geminiUsage struct {
	PromptTokenCount        int `json:"promptTokenCount"`
	CachedContentTokenCount int `json:"cachedContentTokenCount"`
}

type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata geminiUsage       `json:"usageMetadata"`
}

func (b *GeminiBackend) call(system, user string) (string, error) {
	body := geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: system}}},
		Contents:          []geminiContent{{Parts: []geminiPart{{Text: user}}}},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("gemini marshal: %w", err)
	}
	respData, status, err := doWithRetry(b.Client, "POST", b.endpoint(),
		map[string]string{"Content-Type": "application/json"}, data, 4)
	if err != nil {
		return "", fmt.Errorf("gemini request: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("gemini HTTP %d: %s", status, truncateStr(string(respData), 200))
	}
	var geminiResp geminiResponse
	if err := json.Unmarshal(respData, &geminiResp); err != nil {
		return "", fmt.Errorf("gemini decode: %w", err)
	}
	b.stats.add(geminiResp.UsageMetadata.PromptTokenCount, geminiResp.UsageMetadata.CachedContentTokenCount)
	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", nil
	}
	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

func (b *GeminiBackend) classifyOne(msg string) (Classification, error) {
	user := strings.Replace(OneShotUserPrompt, "{commit_message}", msg, 1)
	text, err := b.call(OneShotSystemPrompt, user)
	if err != nil {
		return Clean, err
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "true") {
		return Suspicious, nil
	}
	return Clean, nil
}

func (b *GeminiBackend) Classify(msg string) (Classification, error) {
	return b.classifyOne(msg)
}

func (b *GeminiBackend) ClassifyBatch(msgs []string) (map[int]Classification, error) {
	var parts []string
	for i, m := range msgs {
		parts = append(parts, fmt.Sprintf("[%d] %s", i, m))
	}
	user := strings.Replace(BatchUserPrompt, "{messages}", strings.Join(parts, "\n---\n"), 1)
	text, err := b.call(BatchSystemPrompt, user)
	if err != nil {
		return nil, err
	}
	return parseBatchResponse(text)
}

// ── Anthropic backend ──────────────────────────────────────────────

type AnthropicBackend struct {
	APIKey    string
	Model     string
	Endpoint  string // override for tests/self-hosted gateways
	SessionID string
	Client    *http.Client
	stats     cacheCounters
}

func NewAnthropicBackend(apiKey, model string) *AnthropicBackend {
	if model == "" {
		model = "claude-3-5-haiku-latest"
	}
	return &AnthropicBackend{
		APIKey:    apiKey,
		Model:     model,
		SessionID: newSessionID(),
		Client:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (b *AnthropicBackend) CacheStats() (int64, int64) { return b.stats.get() }

func (b *AnthropicBackend) endpoint() string {
	if b.Endpoint != "" {
		return b.Endpoint
	}
	return "https://api.anthropic.com/v1/messages"
}

func (b *AnthropicBackend) headers() map[string]string {
	return map[string]string{
		"Content-Type":      "application/json",
		"x-api-key":         b.APIKey,
		"anthropic-version": "2023-06-01",
	}
}

type anthropicSystemBlock struct {
	Type         string                 `json:"type"`
	Text         string                 `json:"text"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
}

type anthropicCacheControl struct {
	Type string `json:"type"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string                 `json:"model"`
	MaxTokens int                    `json:"max_tokens"`
	System    []anthropicSystemBlock `json:"system,omitempty"`
	Messages  []anthropicMessage     `json:"messages"`
}

type anthropicContent struct {
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
	Usage   anthropicUsage     `json:"usage"`
}

// call sends one request. The stable instruction goes in a system block
// marked cache_control: ephemeral — without that breakpoint Anthropic does
// not cache at all.
func (b *AnthropicBackend) call(system, user string, maxTokens int) (string, error) {
	body := anthropicRequest{
		Model:     b.Model,
		MaxTokens: maxTokens,
		System: []anthropicSystemBlock{{
			Type:         "text",
			Text:         system,
			CacheControl: &anthropicCacheControl{Type: "ephemeral"},
		}},
		Messages: []anthropicMessage{{Role: "user", Content: user}},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("anthropic marshal: %w", err)
	}
	respData, status, err := doWithRetry(b.Client, "POST", b.endpoint(), b.headers(), data, 4)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("anthropic HTTP %d: %s", status, truncateStr(string(respData), 200))
	}
	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respData, &anthropicResp); err != nil {
		return "", fmt.Errorf("anthropic decode: %w", err)
	}
	u := anthropicResp.Usage
	// input_tokens excludes cache reads/writes; total prompt = sum of three.
	b.stats.add(u.InputTokens+u.CacheReadInputTokens+u.CacheCreationInputTokens, u.CacheReadInputTokens)
	if len(anthropicResp.Content) == 0 {
		return "", nil
	}
	return anthropicResp.Content[0].Text, nil
}

func (b *AnthropicBackend) classifyOne(msg string) (Classification, error) {
	user := strings.Replace(OneShotUserPrompt, "{commit_message}", msg, 1)
	text, err := b.call(OneShotSystemPrompt, user, 64)
	if err != nil {
		return Clean, err
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "true") {
		return Suspicious, nil
	}
	return Clean, nil
}

func (b *AnthropicBackend) Classify(msg string) (Classification, error) {
	return b.classifyOne(msg)
}

func (b *AnthropicBackend) ClassifyBatch(msgs []string) (map[int]Classification, error) {
	var parts []string
	for i, m := range msgs {
		parts = append(parts, fmt.Sprintf("[%d] %s", i, m))
	}
	user := strings.Replace(BatchUserPrompt, "{messages}", strings.Join(parts, "\n---\n"), 1)
	text, err := b.call(BatchSystemPrompt, user, 1024)
	if err != nil {
		return nil, err
	}
	return parseBatchResponse(text)
}

// ── Helpers ─────────────────────────────────────────────────────────

func parseBatchResponse(text string) (map[int]Classification, error) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	var data map[string]bool
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, fmt.Errorf("batch json decode: %w", err)
	}

	result := make(map[int]Classification, len(data))
	for k, v := range data {
		idx, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		if v {
			result[idx] = Suspicious
		} else {
			result[idx] = Clean
		}
	}
	return result, nil
}

func DetectLLMProvider(apiKey string) string {
	if strings.HasPrefix(apiKey, "sk-ant") {
		return "anthropic"
	}
	if strings.HasPrefix(apiKey, "sk-") {
		return "openai"
	}
	if strings.HasPrefix(apiKey, "AIza") {
		return "gemini"
	}
	if strings.HasPrefix(apiKey, "oc_sk_") {
		return "opencode-go"
	}
	return "openai"
}

// ── Factory ────────────────────────────────────────────────────────

func BuildLLMBackend(provider, endpoint, apiKey, model string) LLMBackend {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "opencode" {
		provider = "opencode-go"
	}
	preset, ok := LLMProviderPresets[provider]
	if !ok {
		log.Printf("unknown LLM provider %q — AI fallback disabled", provider)
		return nil
	}
	if endpoint == "" {
		endpoint = preset.Endpoint
	}
	if model == "" {
		model = preset.Model
	}

	switch provider {
	case "anthropic":
		if apiKey == "" {
			log.Printf("anthropic requires an API key — AI fallback disabled")
			return nil
		}
		return NewAnthropicBackend(apiKey, model)
	case "gemini":
		if apiKey == "" {
			log.Printf("gemini requires an API key — AI fallback disabled")
			return nil
		}
		return NewGeminiBackend(apiKey, model)
	default:
		// OpenAI and every OpenAI-compatible gateway (OpenCode Go, custom).
		if endpoint == "" {
			log.Printf("%s requires --llm-endpoint — AI fallback disabled", provider)
			return nil
		}
		b := NewOpenAICompatibleBackend(provider, endpoint, apiKey, model, "")
		b.PromptCacheKey = provider == "openai"
		if provider == "opencode-go" {
			// Session affinity: the OpenCode Go gateway uses this header to
			// keep a conversation on the same warm cache shard.
			if b.ExtraHeaders == nil {
				b.ExtraHeaders = map[string]string{}
			}
			b.ExtraHeaders["x-opencode-session"] = b.SessionID
		}
		return b
	}
}
