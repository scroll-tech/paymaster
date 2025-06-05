// Package controller provides the main controller for handling JSON-RPC requests in the Scroll paymaster service.
package controller

import (
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/types"
)

// PaymasterCtl paymaster controller instance
var PaymasterCtl *PaymasterController

// AdminCtl admin controller instance
var AdminCtl *AdminController

// InitAPI init api handler
func InitAPI(cfg *config.Config, db *gorm.DB) {
	PaymasterCtl = NewPaymasterController(cfg, db)
	AdminCtl = NewAdminController(cfg, db)
}

// UnifiedHandler handles all JSON-RPC requests
func UnifiedHandler(c *gin.Context) {
	var req types.PaymasterJSONRPCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		types.SendError(c, nil, types.ParseErrorCode, "Parse error")
		return
	}

	if req.JSONRPC != types.JSONRPCVersion {
		types.SendError(c, req.ID, types.InvalidRequestCode, "Invalid JSON-RPC version")
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		types.SendError(c, nil, types.UnauthorizedErrorCode, "Missing or invalid Authorization header")
		return
	}

	apiKey := strings.TrimPrefix(authHeader, "Bearer ")
	if apiKey != AdminCtl.cfg.APIKey {
		types.SendError(c, nil, types.UnauthorizedErrorCode, "Invalid API key")
		return
	}

	switch req.Method {
	case "pm_getPaymasterStubData", "pm_getPaymasterData":
		PaymasterCtl.handlePaymasterMethod(c, req, apiKey)

	case "pm_listPolicies", "pm_getPolicyByID", "pm_createPolicy", "pm_updatePolicy", "pm_deletePolicy":
		AdminCtl.handleAdminMethod(c, req, apiKey)

	default:
		log.Debug("Method not found", "method", req.Method)
		types.SendError(c, req.ID, types.MethodNotFoundCode, "Method not found: "+req.Method)
	}
}
