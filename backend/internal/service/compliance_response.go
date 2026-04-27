package service

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *GatewayService) enforceAnthropicOutputCompliance(ctx context.Context, c *gin.Context, body []byte) error {
	if s == nil || s.complianceModerationService == nil {
		return nil
	}
	_, err := s.complianceModerationService.CheckOutput(ctx, ComplianceProtocolAnthropicMessages, body)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrComplianceBlocked) {
		c.JSON(http.StatusForbidden, gin.H{
			"type": "error",
			"error": gin.H{
				"type":    "permission_error",
				"message": "content blocked by compliance moderation",
			},
		})
		return err
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"type": "error",
		"error": gin.H{
			"type":    "moderation_unavailable",
			"message": "compliance moderation unavailable",
		},
	})
	return err
}

func (s *OpenAIGatewayService) enforceOpenAIOutputCompliance(ctx context.Context, c *gin.Context, protocol string, body []byte) error {
	if s == nil || s.complianceModerationService == nil {
		return nil
	}
	return enforceOpenAIOutputComplianceWithService(ctx, c, s.complianceModerationService, protocol, body)
}

func (s *GatewayService) enforceOpenAIOutputCompliance(ctx context.Context, c *gin.Context, protocol string, body []byte) error {
	if s == nil || s.complianceModerationService == nil {
		return nil
	}
	return enforceOpenAIOutputComplianceWithService(ctx, c, s.complianceModerationService, protocol, body)
}

func enforceOpenAIOutputComplianceWithService(ctx context.Context, c *gin.Context, moderator *ComplianceModerationService, protocol string, body []byte) error {
	_, err := moderator.CheckOutput(ctx, protocol, body)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrComplianceBlocked) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": gin.H{
				"type":    "content_policy_violation",
				"message": "content blocked by compliance moderation",
			},
		})
		return err
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": gin.H{
			"type":    "moderation_unavailable",
			"message": "compliance moderation unavailable",
		},
	})
	return err
}
