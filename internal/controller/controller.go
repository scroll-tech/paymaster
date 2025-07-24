// Package controller provides the main controller for handling JSON-RPC requests in the Scroll paymaster service.
package controller

import (
	"strconv"

	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/types"
	"github.com/scroll-tech/paymaster/internal/utils"
)

var (
	paymasterCtl *PaymasterController
	adminCtl     *AdminController
)

// InitAPI init api handler
func InitAPI(cfg *config.Config, db *gorm.DB) {
	paymasterCtl = NewPaymasterController(cfg, db)
	adminCtl = NewAdminController(cfg, db)
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

	// Get API key from GIN context, which is fetched by the AuthMiddleware
	apiKeyRaw, exists := c.Get("api_key")
	if !exists {
		types.SendError(c, req.ID, types.UnauthorizedErrorCode, "Unauthorized: API key required in Authorization header")
		return
	}

	apiKey, ok := apiKeyRaw.(string)
	if !ok || apiKey == "" {
		types.SendError(c, req.ID, types.UnauthorizedErrorCode, "Unauthorized: Invalid API key format")
		return
	}

	// Still validate the API key against the config to verify some settings in unit tests
	if !utils.IsValidAPIKey(apiKey, adminCtl.cfg.APIKeys) {
		log.Debug("Unauthorized: Invalid API key", "provided", apiKey)
		types.SendError(c, req.ID, types.UnauthorizedErrorCode, "Unauthorized: Invalid API key")
		return
	}

	switch req.Method {
	case "pm_getPaymasterStubData", "pm_getPaymasterData":
		paymasterCtl.handlePaymasterMethod(c, req, apiKey)

	case "pm_listPolicies", "pm_getPolicyByID", "pm_createPolicy", "pm_updatePolicy", "pm_deletePolicy":
		adminCtl.handleAdminMethod(c, req, apiKey)

	default:
		log.Debug("Method not found", "method", req.Method)
		types.SendError(c, req.ID, types.MethodNotFoundCode, "Method not found: "+req.Method)
	}
}

// GetUsageStats handles GET /api/usage/:address/:policyId requests
func GetUsageStats(c *gin.Context) {
	// Get API key from middleware
	apiKeyRaw, exists := c.Get("api_key")
	if !exists {
		types.SendError(c, nil, types.UnauthorizedErrorCode, "Unauthorized: API key required")
		return
	}

	apiKey, ok := apiKeyRaw.(string)
	if !ok || apiKey == "" {
		types.SendError(c, nil, types.UnauthorizedErrorCode, "Unauthorized: Invalid API key format")
		return
	}

	address := c.Param("address")
	if address == "" {
		types.SendError(c, nil, types.InvalidParamsCode, "Address required")
		return
	}

	policyIDStr := c.Param("policyId")
	if policyIDStr == "" {
		types.SendError(c, nil, types.InvalidParamsCode, "Policy ID required")
		return
	}

	policyID, err := strconv.ParseInt(policyIDStr, 10, 64)
	if err != nil {
		types.SendError(c, nil, types.InvalidParamsCode, "Invalid policy ID")
		return
	}

	paymasterCtl.GetUsageStats(c, apiKey, address, policyID)
}
