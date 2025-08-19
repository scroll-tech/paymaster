// Package controller provides the admin API controller for managing policies and paymaster data.
package controller

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/orm"
	"github.com/scroll-tech/paymaster/internal/types"
)

// AdminController handles admin API requests
type AdminController struct {
	cfg       *config.Config
	policyOrm *orm.Policy
}

// NewAdminController creates a new AdminController
func NewAdminController(cfg *config.Config, db *gorm.DB) *AdminController {
	return &AdminController{
		cfg:       cfg,
		policyOrm: orm.NewPolicy(db),
	}
}

// handleAdminMethod handles JSON-RPC requests for admin methods
func (ac *AdminController) handleAdminMethod(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	switch req.Method {
	case "pm_listPolicies":
		ac.handleListPolicies(c, req, apiKey)
	case "pm_getPolicyByID":
		ac.handleGetPolicyByID(c, req, apiKey)
	case "pm_createPolicy":
		ac.handleCreatePolicy(c, req, apiKey)
	case "pm_updatePolicy":
		ac.handleUpdatePolicy(c, req, apiKey)
	case "pm_deletePolicy":
		ac.handleDeletePolicy(c, req, apiKey)
	default:
		log.Debug("Admin method not found", "method", req.Method)
		types.SendError(c, req.ID, types.MethodNotFoundCode, "Method not found: "+req.Method)
	}
}

// handleListPolicies lists all policies for the API key
func (ac *AdminController) handleListPolicies(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	policies, err := ac.policyOrm.GetByAPIKey(c.Request.Context(), apiKey)
	if err != nil {
		log.Error("Failed to list policies", "error", err, "apiKey", apiKey)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to retrieve policies")
		return
	}

	var result []types.PolicyResponse
	for _, policy := range policies {
		result = append(result, types.PolicyResponse{
			PolicyID:   policy.PolicyID,
			PolicyName: policy.PolicyName,
			Limits:     policy.Limits,
			CreatedAt:  policy.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:  policy.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	log.Debug("Listed policies", "apiKey", apiKey, "count", len(result))
	types.SendSuccess(c, req.ID, result)
}

// handleGetPolicyByID retrieves a specific policy by ID
func (ac *AdminController) handleGetPolicyByID(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	var params struct {
		PolicyID *int64 `json:"policy_id"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "Invalid params structure")
		return
	}

	if params.PolicyID == nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id is required")
		return
	}

	if *params.PolicyID < 0 {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id must be positive")
		return
	}

	policyID := *params.PolicyID

	policy, err := ac.policyOrm.GetByAPIKeyAndPolicyID(c.Request.Context(), apiKey, policyID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			types.SendError(c, req.ID, types.PolicyNotFoundCode, "Policy not found")
			return
		}
		log.Error("Failed to get policy", "error", err, "apiKey", apiKey, "policyID", policyID)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to retrieve policy")
		return
	}

	result := types.PolicyResponse{
		PolicyID:   policy.PolicyID,
		PolicyName: policy.PolicyName,
		Limits:     policy.Limits,
		CreatedAt:  policy.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  policy.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	log.Debug("Retrieved policy", "apiKey", apiKey, "policyID", policyID, "policyName", policy.PolicyName, "limits", policy.Limits)
	types.SendSuccess(c, req.ID, result)
}

// handleCreatePolicy creates a new policy
func (ac *AdminController) handleCreatePolicy(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	var params struct {
		PolicyID   *int64           `json:"policy_id"`
		PolicyName string           `json:"policy_name"`
		Limits     orm.PolicyLimits `json:"limits"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "Invalid params structure")
		return
	}

	if params.PolicyID == nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id is required")
		return
	}

	if *params.PolicyID < 0 {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id must be positive")
		return
	}

	policyID := *params.PolicyID

	if params.PolicyName == "" {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_name is required")
		return
	}

	// Validate limits
	if err := ac.validatePolicyLimits(&params.Limits); err != nil {
		types.SendError(c, req.ID, types.PolicyValidationErrorCode, "Invalid limits: "+err.Error())
		return
	}

	newPolicy := &orm.Policy{
		APIKeyHash: crypto.Keccak256Hash([]byte(apiKey)).Hex(),
		PolicyID:   policyID,
		PolicyName: params.PolicyName,
		Limits:     params.Limits,
	}

	if err := ac.policyOrm.Create(c.Request.Context(), newPolicy); err != nil {
		log.Error("Failed to create policy", "error", err, "apiKey", apiKey)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to create policy")
		return
	}

	result := types.AdminOperationResponse{
		Success: true,
		Message: "Policy created successfully",
	}

	log.Info("Policy created", "apiKey", apiKey, "policyID", policyID, "policyName", params.PolicyName, "limits", params.Limits)
	types.SendSuccess(c, req.ID, result)
}

// handleUpdatePolicy updates an existing policy
func (ac *AdminController) handleUpdatePolicy(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	var params struct {
		PolicyID   *int64            `json:"policy_id"`
		PolicyName *string           `json:"policy_name,omitempty"`
		Limits     *orm.PolicyLimits `json:"limits,omitempty"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "Invalid params structure")
		return
	}

	if params.PolicyID == nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id is required")
		return
	}

	if *params.PolicyID < 0 {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id must be positive")
		return
	}

	policyID := *params.PolicyID

	// Validate limits if provided
	if params.Limits != nil {
		if err := ac.validatePolicyLimits(params.Limits); err != nil {
			types.SendError(c, req.ID, types.PolicyValidationErrorCode, "Invalid limits: "+err.Error())
			return
		}
	}

	// Check if policy exists
	if _, err := ac.policyOrm.GetByAPIKeyAndPolicyID(c.Request.Context(), apiKey, policyID); err != nil {
		if err == gorm.ErrRecordNotFound {
			types.SendError(c, req.ID, types.PolicyNotFoundCode, "Policy not found")
			return
		}
		log.Error("Failed to check policy existence", "error", err, "apiKey", apiKey, "policyID", policyID)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to check policy")
		return
	}

	// Build updates map
	updates := make(map[string]interface{})
	if params.PolicyName != nil {
		updates["policy_name"] = *params.PolicyName
	}
	if params.Limits != nil {
		var limitsJSON []byte
		limitsJSON, err := json.Marshal(*params.Limits)
		if err != nil {
			types.SendError(c, req.ID, types.InternalErrorCode, "Failed to serialize limits")
			return
		}
		updates["limits"] = string(limitsJSON)
	}

	if len(updates) == 0 {
		types.SendError(c, req.ID, types.InvalidParamsCode, "No update parameters provided")
		return
	}

	// Perform update
	if err := ac.policyOrm.Update(c.Request.Context(), apiKey, policyID, updates); err != nil {
		log.Error("Failed to update policy", "error", err, "apiKey", apiKey, "policyID", policyID)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to update policy")
		return
	}

	result := types.AdminOperationResponse{
		Success: true,
		Message: "Policy updated successfully",
	}

	log.Info("Policy updated", "apiKey", apiKey, "policyID", policyID, "updates", updates)
	types.SendSuccess(c, req.ID, result)
}

// handleDeletePolicy deletes a policy
func (ac *AdminController) handleDeletePolicy(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	var params struct {
		PolicyID *int64 `json:"policy_id"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "Invalid params structure")
		return
	}

	if params.PolicyID == nil {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id is required")
		return
	}

	if *params.PolicyID < 0 {
		types.SendError(c, req.ID, types.InvalidParamsCode, "policy_id must be positive")
		return
	}

	policyID := *params.PolicyID

	// Check if policy exists
	if _, err := ac.policyOrm.GetByAPIKeyAndPolicyID(c.Request.Context(), apiKey, policyID); err != nil {
		if err == gorm.ErrRecordNotFound {
			types.SendError(c, req.ID, types.PolicyNotFoundCode, "Policy not found")
			return
		}
		log.Error("Failed to check policy existence", "error", err, "apiKey", apiKey, "policyID", policyID)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to check policy")
		return
	}

	// Perform deletion (soft delete)
	if err := ac.policyOrm.Delete(c.Request.Context(), apiKey, policyID); err != nil {
		log.Error("Failed to delete policy", "error", err, "apiKey", apiKey, "policyID", policyID)
		types.SendError(c, req.ID, types.InternalServerError, "Failed to delete policy")
		return
	}

	result := types.AdminOperationResponse{
		Success: true,
		Message: "Policy deleted successfully",
	}

	log.Info("Policy deleted", "apiKey", apiKey, "policyID", policyID)
	types.SendSuccess(c, req.ID, result)
}

// validatePolicyLimits validates the policy limits structure
func (ac *AdminController) validatePolicyLimits(limits *orm.PolicyLimits) error {
	if limits == nil {
		return fmt.Errorf("limits cannot be nil")
	}

	// Validate MaxTransactionsPerWalletPerWindow (required)
	if limits.MaxTransactionsPerWalletPerWindow <= 0 {
		return fmt.Errorf("max_transactions_per_wallet_per_window must be positive")
	}

	if limits.MaxTransactionsPerWalletPerWindow > 1000000 {
		return fmt.Errorf("max_transactions_per_wallet_per_window cannot exceed 1000000")
	}

	// Validate MaxEthPerWalletPerWindow (required)
	if limits.MaxEthPerWalletPerWindow == "" {
		return fmt.Errorf("max_eth_per_wallet_per_window is required")
	}
	maxEthFloat, success := new(big.Float).SetPrec(256).SetString(limits.MaxEthPerWalletPerWindow)
	if !success {
		return fmt.Errorf("invalid max_eth_per_wallet_per_window format: %s", limits.MaxEthPerWalletPerWindow)
	}
	// Check if it's positive
	if maxEthFloat.Cmp(big.NewFloat(0)) <= 0 {
		return fmt.Errorf("max_eth_per_wallet_per_window must be positive: %s", limits.MaxEthPerWalletPerWindow)
	}

	// Check if conversion to wei results in an integer (no precision loss)
	weiPerEth := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	maxLimitWei, accuracy := new(big.Float).Mul(maxEthFloat, new(big.Float).SetInt(weiPerEth)).Int(nil)
	if accuracy != big.Exact {
		return fmt.Errorf("max_eth_per_wallet_per_window has too many decimal places (max 18): original=%s, converted_wei=%s, accuracy=%d", limits.MaxEthPerWalletPerWindow, maxLimitWei.String(), accuracy)
	}

	// Check if it's at least 1 wei
	if maxLimitWei.Cmp(big.NewInt(1)) < 0 {
		return fmt.Errorf("max_eth_per_wallet_per_window must be at least 1 wei (0.000000000000000001 ETH): %s, maxLimitWei: %s", limits.MaxEthPerWalletPerWindow, maxLimitWei.String())
	}

	// Validate TimeWindowHours (required)
	if limits.TimeWindowHours <= 0 {
		return fmt.Errorf("time_window_hours must be positive: %d", limits.TimeWindowHours)
	}
	if limits.TimeWindowHours > 8760 { // 8760 hours = 1 year
		return fmt.Errorf("time_window_hours cannot exceed 8760 hours (1 year): %d", limits.TimeWindowHours)
	}

	return nil
}
