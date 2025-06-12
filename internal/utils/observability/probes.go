// Package observability provides observability API for the Scroll paymaster service.
package observability

import (
	"github.com/gin-gonic/gin"

	"github.com/scroll-tech/paymaster/internal/types"
)

// ProbesController probe check controller
type ProbesController struct{}

// NewProbesController returns an ProbesController instance
func NewProbesController() *ProbesController {
	return &ProbesController{}
}

// HealthCheck the api controller for health check
func (a *ProbesController) HealthCheck(c *gin.Context) {
	types.RenderSuccess(c, nil)
}

// Ready the api controller for ready check
func (a *ProbesController) Ready(c *gin.Context) {
	types.RenderSuccess(c, nil)
}
