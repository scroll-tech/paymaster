// Package middleware provides middleware functions for the Scroll paymaster service.
package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/juju/ratelimit"

	"github.com/scroll-tech/paymaster/internal/config"
)

// RateLimiter the rate limiter of signature
func RateLimiter(conf *config.Config) gin.HandlerFunc {
	buckets := make(map[string]*ratelimit.Bucket)
	buckets["/"] = ratelimit.NewBucket(time.Second/time.Duration(conf.RateLimiterQPS), conf.RateLimiterQPS)

	return func(c *gin.Context) {
		bucket, ok := buckets[c.Request.URL.Path]
		if !ok {
			c.Next()
			return
		}

		if bucket.TakeAvailable(1) < 1 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			return
		}

		c.Next()
	}
}
