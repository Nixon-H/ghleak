package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// LLMBackend is the interface for AI fallback classification.
type LLMBackend interface {
	Classify(message string) (Classification, error)
	ClassifyBatch(messages []string) (map[int]Classification, error)
}

// ── OpenAI-compatible backend ──────────────────────────────────────

type OpenAIBackend struct {
	Endpoint string
	APIKey   string
	Model    string
	Client   *http.Client
}

func NewOpenAIBackend(endpoint, apiKey, model string) *OpenAIBackend {
	if endpoint == "" {
		endpoint = DefaultLLMEndpoint
	}
	if model == "" {
		model = DefaultLLMModel
	}
	return &OpenAIBackend{
		Endpoint: endpoint,
		APIKey:   apiKey,
		Model:    model,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
}

func (b *OpenAIBackend) doRequest(req openAIRequest) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("llm marshal: %w", err)
	}

	httpReq, err := http.NewRequest("POST", b.Endpoint, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if b.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+b.APIKey)
	}

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("llm do: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("llm read: %w", err)
	}

	var openAIResp openAIResponse
	if err := json.Unmarshal(respData, &openAIResp); err != nil {
		return "", fmt.Errorf("llm decode: %w", err)
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("llm no choices")
	}

	return strings.TrimSpace(openAIResp.Choices[0].Message.Content), nil
}

func (b *OpenAIBackend) classifyOne(msg string) (Classification, error) {
	prompt := strings.Replace(OneShotPrompt, "{commit_message}", msg, 1)
	body := openAIRequest{
		Model: b.Model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.0,
		MaxTokens:   64,
	}
	text, err := b.doRequest(body)
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
	batchText := strings.Join(parts, "\n---\n")
	prompt := strings.Replace(BatchPrompt, "{messages}", batchText, 1)

	body := openAIRequest{
		Model: b.Model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.0,
		MaxTokens:   1024,
	}
	text, err := b.doRequest(body)
	if err != nil {
		return nil, err
	}
	return parseBatchResponse(text)
}

// ── Gemini backend ─────────────────────────────────────────────────

type GeminiBackend struct {
	APIKey string
	Model  string
	Client *http.Client
}

func NewGeminiBackend(apiKey, model string) *GeminiBackend {
	if model == "" {
		model = DefaultLLMModel
	}
	return &GeminiBackend{
		APIKey: apiKey,
		Model:  model,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

func (b *GeminiBackend) classifyOne(msg string) (Classification, error) {
	prompt := strings.Replace(OneShotPrompt, "{commit_message}", msg, 1)

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		b.Model, b.APIKey)

	body := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return Clean, fmt.Errorf("gemini marshal: %w", err)
	}

	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return Clean, fmt.Errorf("gemini do: %w", err)
	}
	defer resp.Body.Close()

	respData, _ := io.ReadAll(resp.Body)
	var geminiResp geminiResponse
	if err := json.Unmarshal(respData, &geminiResp); err != nil {
		return Clean, fmt.Errorf("gemini decode: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return Clean, nil
	}

	text := strings.ToLower(strings.TrimSpace(geminiResp.Candidates[0].Content.Parts[0].Text))
	if strings.HasPrefix(text, "true") {
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
	batchText := strings.Join(parts, "\n---\n")
	prompt := strings.Replace(BatchPrompt, "{messages}", batchText, 1)

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		b.Model, b.APIKey)

	body := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("gemini batch marshal: %w", err)
	}

	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini batch do: %w", err)
	}
	defer resp.Body.Close()

	respData, _ := io.ReadAll(resp.Body)
	var geminiResp geminiResponse
	if err := json.Unmarshal(respData, &geminiResp); err != nil {
		return nil, fmt.Errorf("gemini batch decode: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini batch no candidates")
	}

	text := strings.TrimSpace(geminiResp.Candidates[0].Content.Parts[0].Text)
	return parseBatchResponse(text)
}

// ── Anthropic backend ──────────────────────────────────────────────

type AnthropicBackend struct {
	APIKey string
	Model  string
	Client *http.Client
}

func NewAnthropicBackend(apiKey, model string) *AnthropicBackend {
	if model == "" {
		model = "claude-3-5-haiku-latest"
	}
	return &AnthropicBackend{
		APIKey: apiKey,
		Model:  model,
		Client: &http.Client{Timeout: 60 * time.Second},
	}
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicContent struct {
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
}

func (b *AnthropicBackend) classifyOne(msg string) (Classification, error) {
	prompt := strings.Replace(OneShotPrompt, "{commit_message}", msg, 1)

	body := anthropicRequest{
		Model:     b.Model,
		MaxTokens: 64,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return Clean, fmt.Errorf("anthropic marshal: %w", err)
	}

	httpReq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", b.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return Clean, fmt.Errorf("anthropic do: %w", err)
	}
	defer resp.Body.Close()

	respData, _ := io.ReadAll(resp.Body)
	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respData, &anthropicResp); err != nil {
		return Clean, nil
	}

	if len(anthropicResp.Content) == 0 {
		return Clean, nil
	}

	text := strings.ToLower(strings.TrimSpace(anthropicResp.Content[0].Text))
	if strings.HasPrefix(text, "true") {
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
	batchText := strings.Join(parts, "\n---\n")
	prompt := strings.Replace(BatchPrompt, "{messages}", batchText, 1)

	body := anthropicRequest{
		Model:     b.Model,
		MaxTokens: 1024,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("anthropic batch marshal: %w", err)
	}

	httpReq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", b.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic batch do: %w", err)
	}
	defer resp.Body.Close()

	respData, _ := io.ReadAll(resp.Body)
	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respData, &anthropicResp); err != nil {
		return nil, fmt.Errorf("anthropic batch decode: %w", err)
	}

	if len(anthropicResp.Content) == 0 {
		return nil, fmt.Errorf("anthropic batch no content")
	}

	text := strings.TrimSpace(anthropicResp.Content[0].Text)
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
	return "openai"
}

// ── Factory ────────────────────────────────────────────────────────

func BuildLLMBackend(provider, endpoint, apiKey, model string) LLMBackend {
	switch provider {
	case "openai", "custom":
		return NewOpenAIBackend(endpoint, apiKey, model)
	case "gemini":
		return NewGeminiBackend(apiKey, model)
	case "anthropic":
		return NewAnthropicBackend(apiKey, model)
	default:
		return nil
	}
}
