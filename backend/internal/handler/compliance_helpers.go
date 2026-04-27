package handler

import (
	"errors"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func checkComplianceInput(
	c *gin.Context,
	moderator *service.ComplianceModerationService,
	protocol string,
	body []byte,
) (status int, openAIType string, anthropicType string, message string, blocked bool) {
	if moderator == nil {
		return 0, "", "", "", false
	}
	result, err := moderator.CheckInput(c.Request.Context(), protocol, body)
	if err == nil || result == nil || !result.Enabled {
		return 0, "", "", "", false
	}
	if errors.Is(err, service.ErrComplianceBlocked) {
		return http.StatusForbidden, "content_policy_violation", "permission_error", "content blocked by compliance moderation", true
	}
	if errors.Is(err, service.ErrComplianceUnavailable) {
		return http.StatusServiceUnavailable, "moderation_unavailable", "moderation_unavailable", "compliance moderation unavailable", true
	}
	return http.StatusServiceUnavailable, "moderation_unavailable", "moderation_unavailable", "compliance moderation unavailable", true
}
