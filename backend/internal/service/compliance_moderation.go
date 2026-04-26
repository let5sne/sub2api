package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tidwall/gjson"
)

const (
	ComplianceStageInput  = "input"
	ComplianceStageOutput = "output"

	ComplianceProtocolAnthropicMessages   = "anthropic_messages"
	ComplianceProtocolOpenAIChat          = "openai_chat_completions"
	ComplianceProtocolOpenAIResponses     = "openai_responses"
	ComplianceProtocolOpenAIResponsesJSON = "openai_responses_json"

	ComplianceDecisionPass   = "pass"
	ComplianceDecisionReview = "review"
	ComplianceDecisionBlock  = "block"
	ComplianceDecisionError  = "error"

	complianceTencentEndpoint = "https://tms.tencentcloudapi.com/"
	complianceTencentService  = "tms"
	complianceTencentVersion  = "2020-12-29"
	complianceTencentAction   = "TextModeration"
	complianceCacheTTL        = 60 * time.Second
)

var (
	ErrComplianceBlocked     = errors.New("compliance moderation blocked content")
	ErrComplianceUnavailable = errors.New("compliance moderation unavailable")
)

type ComplianceModerationRuntimeConfig struct {
	Enabled             bool
	TencentSecretID     string
	TencentSecretKey    string
	TencentRegion       string
	ModerationType      string
	Timeout             time.Duration
	MaxChars            int
	ReviewAction        string
	SecretKeyConfigured bool
}

type ComplianceCheckResult struct {
	Enabled        bool     `json:"enabled"`
	Stage          string   `json:"stage"`
	Protocol       string   `json:"protocol"`
	Decision       string   `json:"decision"`
	Label          string   `json:"label,omitempty"`
	Suggestion     string   `json:"suggestion,omitempty"`
	Score          int      `json:"score,omitempty"`
	Keywords       []string `json:"keywords,omitempty"`
	RequestID      string   `json:"request_id,omitempty"`
	TextHash       string   `json:"text_hash,omitempty"`
	TextBytes      int      `json:"text_bytes,omitempty"`
	TextChars      int      `json:"text_chars,omitempty"`
	Truncated      bool     `json:"truncated,omitempty"`
	SkippedNonText bool     `json:"skipped_non_text,omitempty"`
	Error          string   `json:"error,omitempty"`
}

func (r *ComplianceCheckResult) Blocked() bool {
	if r == nil {
		return false
	}
	return r.Decision == ComplianceDecisionReview || r.Decision == ComplianceDecisionBlock
}

func (r *ComplianceCheckResult) Unavailable() bool {
	return r != nil && r.Decision == ComplianceDecisionError
}

type ComplianceModerationService struct {
	settingService *SettingService
	httpClient     *http.Client
	endpoint       string

	mu          sync.RWMutex
	cached      *ComplianceModerationRuntimeConfig
	cachedUntil time.Time
}

func NewComplianceModerationService(settingService *SettingService) *ComplianceModerationService {
	return &ComplianceModerationService{
		settingService: settingService,
		httpClient:     http.DefaultClient,
		endpoint:       complianceTencentEndpoint,
	}
}

func (s *ComplianceModerationService) CheckInput(ctx context.Context, protocol string, body []byte) (*ComplianceCheckResult, error) {
	return s.check(ctx, ComplianceStageInput, protocol, body)
}

func (s *ComplianceModerationService) CheckOutput(ctx context.Context, protocol string, body []byte) (*ComplianceCheckResult, error) {
	return s.check(ctx, ComplianceStageOutput, protocol, body)
}

func (s *ComplianceModerationService) check(ctx context.Context, stage string, protocol string, body []byte) (*ComplianceCheckResult, error) {
	cfg, err := s.runtimeConfig(ctx)
	if err != nil {
		return nil, err
	}
	result := &ComplianceCheckResult{
		Enabled:  cfg.Enabled,
		Stage:    stage,
		Protocol: protocol,
		Decision: ComplianceDecisionPass,
	}
	if !cfg.Enabled {
		return result, nil
	}
	if strings.TrimSpace(cfg.TencentSecretID) == "" || strings.TrimSpace(cfg.TencentSecretKey) == "" {
		result.Decision = ComplianceDecisionError
		result.Error = "missing Tencent Cloud moderation credentials"
		return result, ErrComplianceUnavailable
	}

	extracted := extractComplianceText(stage, protocol, body)
	result.SkippedNonText = extracted.SkippedNonText
	text := strings.TrimSpace(strings.Join(extracted.Texts, "\n"))
	if text == "" {
		return result, nil
	}
	text = truncateComplianceText(text, cfg.MaxChars, &result.Truncated)
	result.TextBytes = len([]byte(text))
	result.TextChars = utf8.RuneCountInString(text)
	result.TextHash = complianceTextHash(text)

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	moderation, err := s.callTencentTextModeration(ctx, cfg, text)
	if err != nil {
		result.Decision = ComplianceDecisionError
		result.Error = err.Error()
		return result, ErrComplianceUnavailable
	}
	result.RequestID = moderation.RequestID
	result.Label = moderation.Label
	result.Suggestion = moderation.Suggestion
	result.Score = moderation.Score
	result.Keywords = moderation.Keywords
	result.Decision = normalizeComplianceDecision(moderation.Suggestion)
	if result.Decision == ComplianceDecisionReview && strings.EqualFold(cfg.ReviewAction, "pass") {
		result.Decision = ComplianceDecisionPass
	}
	if result.Blocked() {
		return result, ErrComplianceBlocked
	}
	return result, nil
}

func (s *ComplianceModerationService) runtimeConfig(ctx context.Context) (*ComplianceModerationRuntimeConfig, error) {
	if s == nil || s.settingService == nil {
		return &ComplianceModerationRuntimeConfig{Enabled: false}, nil
	}
	now := time.Now()
	s.mu.RLock()
	if s.cached != nil && now.Before(s.cachedUntil) {
		cfg := *s.cached
		s.mu.RUnlock()
		return &cfg, nil
	}
	s.mu.RUnlock()

	settings, err := s.settingService.GetAllSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("load compliance settings: %w", err)
	}
	cfg := &ComplianceModerationRuntimeConfig{
		Enabled:             settings.ComplianceModerationEnabled,
		TencentSecretID:     strings.TrimSpace(settings.ComplianceTencentSecretID),
		TencentSecretKey:    strings.TrimSpace(settings.ComplianceTencentSecretKey),
		TencentRegion:       strings.TrimSpace(settings.ComplianceTencentRegion),
		ModerationType:      strings.TrimSpace(settings.ComplianceModerationType),
		Timeout:             time.Duration(settings.ComplianceModerationTimeoutSeconds) * time.Second,
		MaxChars:            settings.ComplianceModerationMaxChars,
		ReviewAction:        strings.TrimSpace(settings.ComplianceModerationReviewAction),
		SecretKeyConfigured: settings.ComplianceTencentSecretKeyConfigured,
	}
	if cfg.TencentRegion == "" {
		cfg.TencentRegion = "ap-guangzhou"
	}
	if cfg.ModerationType == "" {
		cfg.ModerationType = "TEXT"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Timeout > 30*time.Second {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxChars <= 0 || cfg.MaxChars > 10000 {
		cfg.MaxChars = 10000
	}
	if cfg.ReviewAction == "" {
		cfg.ReviewAction = "block"
	}

	s.mu.Lock()
	s.cached = cfg
	s.cachedUntil = now.Add(complianceCacheTTL)
	s.mu.Unlock()

	out := *cfg
	return &out, nil
}

type complianceExtractedText struct {
	Texts          []string
	SkippedNonText bool
}

func extractComplianceText(stage string, protocol string, body []byte) complianceExtractedText {
	switch protocol {
	case ComplianceProtocolAnthropicMessages:
		if stage == ComplianceStageOutput {
			return extractAnthropicOutputText(body)
		}
		return extractAnthropicInputText(body)
	case ComplianceProtocolOpenAIChat:
		if stage == ComplianceStageOutput {
			return extractOpenAIChatOutputText(body)
		}
		return extractOpenAIChatInputText(body)
	case ComplianceProtocolOpenAIResponses, ComplianceProtocolOpenAIResponsesJSON:
		if stage == ComplianceStageOutput {
			return extractOpenAIResponsesOutputText(body)
		}
		return extractOpenAIResponsesInputText(body)
	default:
		return extractGenericJSONText(body)
	}
}

func extractAnthropicInputText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	if m, ok := root.(map[string]any); ok {
		collectAnthropicSystem(m["system"], &out)
		if messages, ok := m["messages"].([]any); ok {
			for _, item := range messages {
				if msg, ok := item.(map[string]any); ok {
					collectComplianceContent(msg["content"], &out)
				}
			}
		}
	}
	return out
}

func extractAnthropicOutputText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	if m, ok := root.(map[string]any); ok {
		collectComplianceContent(m["content"], &out)
	}
	return out
}

func extractOpenAIChatInputText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	if m, ok := root.(map[string]any); ok {
		if messages, ok := m["messages"].([]any); ok {
			for _, item := range messages {
				if msg, ok := item.(map[string]any); ok {
					collectComplianceContent(msg["content"], &out)
				}
			}
		}
	}
	return out
}

func extractOpenAIChatOutputText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	if m, ok := root.(map[string]any); ok {
		if choices, ok := m["choices"].([]any); ok {
			for _, item := range choices {
				choice, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if msg, ok := choice["message"].(map[string]any); ok {
					collectComplianceContent(msg["content"], &out)
				}
				if delta, ok := choice["delta"].(map[string]any); ok {
					collectComplianceContent(delta["content"], &out)
				}
			}
		}
	}
	return out
}

func extractOpenAIResponsesInputText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	if m, ok := root.(map[string]any); ok {
		if s, ok := m["instructions"].(string); ok && strings.TrimSpace(s) != "" {
			out.Texts = append(out.Texts, s)
		}
		collectOpenAIResponsesValue(m["input"], &out)
	}
	return out
}

func extractOpenAIResponsesOutputText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	if m, ok := root.(map[string]any); ok {
		if s, ok := m["output_text"].(string); ok && strings.TrimSpace(s) != "" {
			out.Texts = append(out.Texts, s)
		}
		collectOpenAIResponsesValue(m["output"], &out)
		collectComplianceContent(m["content"], &out)
	}
	return out
}

func extractGenericJSONText(body []byte) complianceExtractedText {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return complianceExtractedText{}
	}
	var out complianceExtractedText
	collectOpenAIResponsesValue(root, &out)
	return out
}

func collectAnthropicSystem(value any, out *complianceExtractedText) {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			out.Texts = append(out.Texts, v)
		}
	case []any:
		for _, item := range v {
			collectComplianceContent(item, out)
		}
	case map[string]any:
		collectComplianceContent(v, out)
	}
}

func collectComplianceContent(value any, out *complianceExtractedText) {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			out.Texts = append(out.Texts, v)
		}
	case []any:
		for _, item := range v {
			collectComplianceContent(item, out)
		}
	case map[string]any:
		t, _ := v["type"].(string)
		switch t {
		case "", "text", "input_text", "output_text":
			if s, ok := v["text"].(string); ok && strings.TrimSpace(s) != "" {
				out.Texts = append(out.Texts, s)
			} else if s, ok := v["content"].(string); ok && strings.TrimSpace(s) != "" {
				out.Texts = append(out.Texts, s)
			}
		case "image", "image_url", "input_image", "file", "input_file", "tool_result", "tool_use", "function_call", "function_call_output":
			out.SkippedNonText = true
		default:
			if s, ok := v["text"].(string); ok && strings.TrimSpace(s) != "" {
				out.Texts = append(out.Texts, s)
			} else if s, ok := v["content"].(string); ok && strings.TrimSpace(s) != "" {
				out.Texts = append(out.Texts, s)
			} else {
				out.SkippedNonText = true
			}
		}
	}
}

func collectOpenAIResponsesValue(value any, out *complianceExtractedText) {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			out.Texts = append(out.Texts, v)
		}
	case []any:
		for _, item := range v {
			collectOpenAIResponsesValue(item, out)
		}
	case map[string]any:
		t, _ := v["type"].(string)
		switch t {
		case "message":
			collectComplianceContent(v["content"], out)
		case "input_text", "output_text", "text":
			collectComplianceContent(v, out)
		case "input_image", "image", "image_url", "input_file", "file", "tool_result", "tool_use", "function_call", "function_call_output":
			out.SkippedNonText = true
		default:
			if content, ok := v["content"]; ok {
				collectComplianceContent(content, out)
			}
			if text, ok := v["text"]; ok {
				collectComplianceContent(text, out)
			}
		}
	}
}

func truncateComplianceText(text string, maxChars int, truncated *bool) string {
	if maxChars <= 0 {
		maxChars = 10000
	}
	runes := []rune(text)
	if len(runes) <= maxChars {
		return text
	}
	if truncated != nil {
		*truncated = true
	}
	return string(runes[:maxChars])
}

func complianceTextHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

type tencentModerationResult struct {
	Suggestion string
	Label      string
	Score      int
	Keywords   []string
	RequestID  string
}

func (s *ComplianceModerationService) callTencentTextModeration(ctx context.Context, cfg *ComplianceModerationRuntimeConfig, text string) (*tencentModerationResult, error) {
	payload := map[string]any{
		"Content": base64.StdEncoding.EncodeToString([]byte(text)),
		"Type":    firstNonEmpty(cfg.ModerationType, "TEXT"),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := s.endpoint
	if endpoint == "" {
		endpoint = complianceTencentEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	host := u.Host
	timestamp := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", complianceTencentAction)
	req.Header.Set("X-TC-Version", complianceTencentVersion)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-TC-Region", cfg.TencentRegion)
	req.Header.Set("Authorization", tencentTC3Authorization(cfg.TencentSecretID, cfg.TencentSecretKey, host, timestamp, body, req.Header))

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("tencent moderation http status %d", resp.StatusCode)
	}
	if msg := strings.TrimSpace(gjson.GetBytes(respBody, "Response.Error.Message").String()); msg != "" {
		code := strings.TrimSpace(gjson.GetBytes(respBody, "Response.Error.Code").String())
		if code != "" {
			return nil, fmt.Errorf("%s: %s", code, msg)
		}
		return nil, errors.New(msg)
	}

	res := &tencentModerationResult{
		Suggestion: strings.TrimSpace(gjson.GetBytes(respBody, "Response.Suggestion").String()),
		Label:      strings.TrimSpace(gjson.GetBytes(respBody, "Response.Label").String()),
		Score:      int(gjson.GetBytes(respBody, "Response.Score").Int()),
		RequestID:  strings.TrimSpace(gjson.GetBytes(respBody, "Response.RequestId").String()),
	}
	res.Keywords = collectTencentKeywords(respBody)
	return res, nil
}

func collectTencentKeywords(body []byte) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, path := range []string{"Response.Keywords", "Response.DetailResults.#.Keywords", "Response.DetailResults.#.LibResults.#.Keywords"} {
		v := gjson.GetBytes(body, path)
		if !v.Exists() {
			continue
		}
		v.ForEach(func(_, item gjson.Result) bool {
			if item.IsArray() {
				item.ForEach(func(_, nested gjson.Result) bool {
					add(nested.String())
					return true
				})
				return true
			}
			add(item.String())
			return true
		})
	}
	sort.Strings(out)
	if len(out) > 20 {
		return out[:20]
	}
	return out
}

func normalizeComplianceDecision(suggestion string) string {
	switch strings.ToLower(strings.TrimSpace(suggestion)) {
	case "", "pass":
		return ComplianceDecisionPass
	case "review":
		return ComplianceDecisionReview
	case "block":
		return ComplianceDecisionBlock
	default:
		return ComplianceDecisionError
	}
}

func tencentTC3Authorization(secretID, secretKey, host string, timestamp int64, payload []byte, headers http.Header) string {
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	canonicalHeaders := "content-type:" + strings.ToLower(headers.Get("Content-Type")) + "\n" +
		"host:" + strings.ToLower(host) + "\n"
	signedHeaders := "content-type;host"
	hashedRequestPayload := sha256Hex(payload)
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload,
	}, "\n")
	credentialScope := date + "/" + complianceTencentService + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		strconv.FormatInt(timestamp, 10),
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, complianceTencentService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))
	return "TC3-HMAC-SHA256 Credential=" + secretID + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}
