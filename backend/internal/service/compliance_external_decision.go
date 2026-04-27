package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type complianceExternalDecisionRequest struct {
	TenantID       string            `json:"tenant_id"`
	ProjectID      string            `json:"project_id,omitempty"`
	APIKeyID       string            `json:"api_key_id,omitempty"`
	Protocol       string            `json:"protocol"`
	Stage          string            `json:"stage"`
	Model          string            `json:"model,omitempty"`
	Stream         bool              `json:"stream"`
	TargetProvider string            `json:"target_provider,omitempty"`
	TargetRegion   string            `json:"target_region,omitempty"`
	TextHash       string            `json:"text_hash"`
	TextExcerpt    string            `json:"text_excerpt,omitempty"`
	ByteSize       int               `json:"byte_size"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type complianceExternalDecisionResponse struct {
	Decision    string `json:"decision"`
	RoutePolicy string `json:"route_policy"`
	RiskLevel   string `json:"risk_level"`
	EventID     string `json:"event_id"`
	Message     string `json:"message"`
}

func (s *ComplianceModerationService) checkExternalDecision(
	ctx context.Context,
	cfg *ComplianceModerationRuntimeConfig,
	result *ComplianceCheckResult,
	text string,
) (bool, error) {
	decision, err := s.callExternalDecision(ctx, cfg, result, text)
	if err != nil {
		result.Decision = ComplianceDecisionError
		result.Error = err.Error()
		switch strings.ToLower(strings.TrimSpace(cfg.ExternalDecisionFailure)) {
		case "fail_open":
			result.Decision = ComplianceDecisionPass
			return true, nil
		default:
			return true, ErrComplianceUnavailable
		}
	}

	result.RequestID = strings.TrimSpace(decision.EventID)
	result.Label = strings.TrimSpace(decision.RoutePolicy)
	result.Suggestion = strings.TrimSpace(decision.Decision)
	if decision.Message != "" {
		result.Error = strings.TrimSpace(decision.Message)
	}

	switch strings.ToLower(strings.TrimSpace(decision.Decision)) {
	case "allow":
		result.Decision = ComplianceDecisionPass
		return true, nil
	case "review", "redact", "route_domestic_only":
		result.Decision = ComplianceDecisionReview
		return true, ErrComplianceBlocked
	case "block":
		result.Decision = ComplianceDecisionBlock
		return true, ErrComplianceBlocked
	default:
		result.Decision = ComplianceDecisionError
		result.Error = "unknown external compliance decision: " + decision.Decision
		return true, ErrComplianceUnavailable
	}
}

func (s *ComplianceModerationService) callExternalDecision(
	ctx context.Context,
	cfg *ComplianceModerationRuntimeConfig,
	result *ComplianceCheckResult,
	text string,
) (*complianceExternalDecisionResponse, error) {
	endpoint, err := complianceExternalDecisionURL(cfg.ExternalDecisionEndpoint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.ExternalDecisionTimeout)
	defer cancel()

	payload := complianceExternalDecisionRequest{
		TenantID:     firstNonEmpty(cfg.ExternalTenantID, "default"),
		ProjectID:    cfg.ExternalProjectID,
		Protocol:     result.Protocol,
		Stage:        result.Stage,
		TargetRegion: firstNonEmpty(cfg.ExternalTargetRegion, "overseas"),
		TextHash:     result.TextHash,
		TextExcerpt:  truncateExternalDecisionExcerpt(text),
		ByteSize:     result.TextBytes,
		Metadata: map[string]string{
			"text_chars": fmt.Sprintf("%d", result.TextChars),
			"truncated":  fmt.Sprintf("%t", result.Truncated),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	httpClient := s.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("external compliance decision status %d", resp.StatusCode)
	}
	var decision complianceExternalDecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

func complianceExternalDecisionURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("external compliance decision endpoint is empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("external compliance decision endpoint must be absolute")
	}
	if strings.HasSuffix(parsed.Path, "/v1/decision") {
		return parsed.String(), nil
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/decision"
	return parsed.String(), nil
}

func truncateExternalDecisionExcerpt(text string) string {
	const maxRunes = 2000
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	return string(runes[:maxRunes])
}
