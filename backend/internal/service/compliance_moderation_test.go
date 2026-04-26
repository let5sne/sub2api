package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

type complianceSettingRepoStub struct {
	values map[string]string
}

func (r *complianceSettingRepoStub) Get(context.Context, string) (*Setting, error) {
	return nil, ErrSettingNotFound
}
func (r *complianceSettingRepoStub) GetValue(ctx context.Context, key string) (string, error) {
	if v, ok := r.values[key]; ok {
		return v, nil
	}
	return "", ErrSettingNotFound
}
func (r *complianceSettingRepoStub) Set(context.Context, string, string) error { return nil }
func (r *complianceSettingRepoStub) GetMultiple(context.Context, []string) (map[string]string, error) {
	return r.values, nil
}
func (r *complianceSettingRepoStub) SetMultiple(context.Context, map[string]string) error { return nil }
func (r *complianceSettingRepoStub) GetAll(context.Context) (map[string]string, error) {
	out := make(map[string]string, len(r.values))
	for k, v := range r.values {
		out[k] = v
	}
	return out, nil
}
func (r *complianceSettingRepoStub) Delete(context.Context, string) error { return nil }

func TestComplianceExtractors(t *testing.T) {
	tests := []struct {
		name           string
		stage          string
		protocol       string
		body           string
		wantTexts      []string
		wantSkippedNon bool
	}{
		{
			name:           "anthropic input string and text block",
			stage:          ComplianceStageInput,
			protocol:       ComplianceProtocolAnthropicMessages,
			body:           `{"system":"sys","messages":[{"content":"hello"},{"content":[{"type":"text","text":"world"},{"type":"image","source":{}}]}]}`,
			wantTexts:      []string{"sys", "hello", "world"},
			wantSkippedNon: true,
		},
		{
			name:           "openai chat input skips tool block",
			stage:          ComplianceStageInput,
			protocol:       ComplianceProtocolOpenAIChat,
			body:           `{"messages":[{"content":[{"type":"text","text":"hello"},{"type":"tool_result","content":"skip"}]}]}`,
			wantTexts:      []string{"hello"},
			wantSkippedNon: true,
		},
		{
			name:      "responses input instructions and input_text",
			stage:     ComplianceStageInput,
			protocol:  ComplianceProtocolOpenAIResponses,
			body:      `{"instructions":"inst","input":[{"type":"message","content":[{"type":"input_text","text":"ask"}]}]}`,
			wantTexts: []string{"inst", "ask"},
		},
		{
			name:      "openai responses output",
			stage:     ComplianceStageOutput,
			protocol:  ComplianceProtocolOpenAIResponses,
			body:      `{"output_text":"answer","output":[{"type":"message","content":[{"type":"output_text","text":"detail"}]}]}`,
			wantTexts: []string{"answer", "detail"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractComplianceText(tt.stage, tt.protocol, []byte(tt.body))
			if strings.Join(got.Texts, "|") != strings.Join(tt.wantTexts, "|") {
				t.Fatalf("texts mismatch: got %#v want %#v", got.Texts, tt.wantTexts)
			}
			if got.SkippedNonText != tt.wantSkippedNon {
				t.Fatalf("skipped mismatch: got %v want %v", got.SkippedNonText, tt.wantSkippedNon)
			}
		})
	}
}

func TestComplianceTencentClientAndDecisionMapping(t *testing.T) {
	var capturedContent string
	var capturedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TC-Action") != complianceTencentAction {
			t.Fatalf("missing action header: %s", r.Header.Get("X-TC-Action"))
		}
		capturedAuth = r.Header.Get("Authorization")
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		capturedContent = req["Content"]
		_, _ = w.Write([]byte(`{"Response":{"Suggestion":"Review","Label":"Polity","Score":88,"Keywords":["kw"],"RequestId":"req-1"}}`))
	}))
	defer ts.Close()

	repo := &complianceSettingRepoStub{values: map[string]string{
		SettingKeyComplianceModerationEnabled:        "true",
		SettingKeyComplianceTencentSecretID:          "sid",
		SettingKeyComplianceTencentSecretKey:         "skey",
		SettingKeyComplianceTencentRegion:            "ap-guangzhou",
		SettingKeyComplianceModerationType:           "TEXT",
		SettingKeyComplianceModerationTimeoutSeconds: "3",
		SettingKeyComplianceModerationMaxChars:       "10000",
		SettingKeyComplianceModerationReviewAction:   "block",
	}}
	svc := NewComplianceModerationService(NewSettingService(repo, &config.Config{}))
	svc.endpoint = ts.URL + "/"
	svc.httpClient = ts.Client()

	result, err := svc.CheckInput(context.Background(), ComplianceProtocolOpenAIChat, []byte(`{"messages":[{"content":"bad"}]}`))
	if err != ErrComplianceBlocked {
		t.Fatalf("expected blocked error, got result=%#v err=%v", result, err)
	}
	if result.Decision != ComplianceDecisionReview || result.RequestID != "req-1" || result.Label != "Polity" {
		t.Fatalf("unexpected result: %#v", result)
	}
	decoded, err := base64.StdEncoding.DecodeString(capturedContent)
	if err != nil || string(decoded) != "bad" {
		t.Fatalf("content not base64 text: decoded=%q err=%v", decoded, err)
	}
	if !strings.Contains(capturedAuth, "TC3-HMAC-SHA256 Credential=sid/") {
		t.Fatalf("missing TC3 authorization: %s", capturedAuth)
	}
}

func TestComplianceUnavailableFailClosed(t *testing.T) {
	repo := &complianceSettingRepoStub{values: map[string]string{
		SettingKeyComplianceModerationEnabled:        "true",
		SettingKeyComplianceTencentSecretID:          "sid",
		SettingKeyComplianceTencentSecretKey:         "",
		SettingKeyComplianceModerationTimeoutSeconds: "1",
	}}
	svc := NewComplianceModerationService(NewSettingService(repo, &config.Config{}))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := svc.CheckInput(ctx, ComplianceProtocolOpenAIChat, []byte(`{"messages":[{"content":"hello"}]}`))
	if err != ErrComplianceUnavailable {
		t.Fatalf("expected unavailable, got result=%#v err=%v", result, err)
	}
	if result.Decision != ComplianceDecisionError {
		t.Fatalf("expected error decision, got %#v", result)
	}
}
