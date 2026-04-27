package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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

	complianceCacheTTL = 60 * time.Second
)

var (
	ErrComplianceBlocked     = errors.New("compliance moderation blocked content")
	ErrComplianceUnavailable = errors.New("compliance moderation unavailable")
)

type ComplianceModerationRuntimeConfig struct {
	Enabled                  bool
	Timeout                  time.Duration
	MaxChars                 int
	ExternalDecisionEnabled  bool
	ExternalDecisionEndpoint string
	ExternalDecisionTimeout  time.Duration
	ExternalDecisionFailure  string
	ExternalTenantID         string
	ExternalProjectID        string
	ExternalTargetRegion     string
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

	if !cfg.ExternalDecisionEnabled || strings.TrimSpace(cfg.ExternalDecisionEndpoint) == "" {
		result.Decision = ComplianceDecisionError
		result.Error = "external compliance decision service is not configured"
		return result, ErrComplianceUnavailable
	}
	_, err = s.checkExternalDecision(ctx, cfg, result, text)
	return result, err
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
		Enabled:                  settings.ComplianceModerationEnabled,
		Timeout:                  time.Duration(settings.ComplianceModerationTimeoutSeconds) * time.Second,
		MaxChars:                 settings.ComplianceModerationMaxChars,
		ExternalDecisionEnabled:  settings.ComplianceExternalDecisionEnabled,
		ExternalDecisionEndpoint: strings.TrimSpace(settings.ComplianceExternalDecisionEndpoint),
		ExternalDecisionTimeout:  time.Duration(settings.ComplianceExternalDecisionTimeout) * time.Second,
		ExternalDecisionFailure:  strings.TrimSpace(settings.ComplianceExternalDecisionFailure),
		ExternalTenantID:         strings.TrimSpace(settings.ComplianceExternalTenantID),
		ExternalProjectID:        strings.TrimSpace(settings.ComplianceExternalProjectID),
		ExternalTargetRegion:     strings.TrimSpace(settings.ComplianceExternalTargetRegion),
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
	if cfg.ExternalDecisionTimeout <= 0 {
		cfg.ExternalDecisionTimeout = 3 * time.Second
	}
	if cfg.ExternalDecisionTimeout > 30*time.Second {
		cfg.ExternalDecisionTimeout = 30 * time.Second
	}
	if cfg.ExternalDecisionFailure == "" {
		cfg.ExternalDecisionFailure = "fail_closed"
	}
	if cfg.ExternalTenantID == "" {
		cfg.ExternalTenantID = "default"
	}
	if cfg.ExternalTargetRegion == "" {
		cfg.ExternalTargetRegion = "overseas"
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
