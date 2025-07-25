// Package middleware provides middleware functions for the Scroll paymaster service.
package middleware

import (
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"
	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/types"
	"github.com/scroll-tech/paymaster/internal/utils"
)

// AuthMiddleware validates API key from Authorization header
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract API key from Authorization header
		apiKey := extractAPIKey(c)

		if apiKey == "" {
			log.Debug("Unauthorized: API key missing from header")
			types.SendError(c, nil, types.UnauthorizedErrorCode, "Unauthorized: API key required in Authorization header")
			c.Abort()
			return
		}

		if !utils.IsValidAPIKey(apiKey, cfg.APIKeys) {
			log.Debug("Unauthorized: Invalid API key", "provided", apiKey)
			types.SendError(c, nil, types.UnauthorizedErrorCode, "Unauthorized: Invalid API key")
			c.Abort()
			return
		}

		// Store validated API key in context for later use
		c.Set("api_key", apiKey)

		c.Next()
	}
}

// extractAPIKey extracts API key from Authorization Bearer header
func extractAPIKey(c *gin.Context) string {
	auth := c.GetHeader("Authorization")

	// Only support Bearer token format
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}
