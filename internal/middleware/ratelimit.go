// Package middleware provides middleware functions for the Scroll paymaster service.
package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/juju/ratelimit"

	"github.com/scroll-tech/paymaster/internal/config"
)

// RateLimiter the rate limiter for all endpoints
func RateLimiter(conf *config.Config) gin.HandlerFunc {
	// Single bucket for all endpoints
	bucket := ratelimit.NewBucket(time.Second/time.Duration(conf.RateLimiterQPS), conf.RateLimiterQPS)

	return func(c *gin.Context) {
		if bucket.TakeAvailable(1) < 1 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			return
		}

		c.Next()
	}
}
