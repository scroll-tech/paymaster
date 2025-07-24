// Package controller provides the PaymasterController for handling usage statistics
package controller

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"

	"github.com/scroll-tech/paymaster/internal/types"
)

// GetUsageStats returns usage statistics for a wallet and policy
func (pc *PaymasterController) GetUsageStats(c *gin.Context, apiKey string, address string, policyID int64) {
	// Get policy
	policy, err := pc.policyOrm.GetByAPIKeyAndPolicyID(c.Request.Context(), apiKey, policyID)
	if err != nil {
		log.Error("Failed to get policy", "policy_id", policyID, "address", address, "error", err)
		types.SendRESTError(c, types.InternalErrorCode, "Failed to get policy")
		return
	}

	// Parse max ETH limit
	maxEthLimit, ok := new(big.Float).SetString(policy.Limits.MaxEthPerWalletPerWindow)
	if !ok {
		log.Error("Invalid MaxEthPerWalletPerWindow format", "policy_id", policyID, "address", address, "policy_name", policy.PolicyName, "value", policy.Limits.MaxEthPerWalletPerWindow)
		types.SendRESTError(c, types.InternalErrorCode, "Invalid policy configuration")
		return
	}

	// Get current usage stats in a single query
	usageStats, err := pc.userOperationOrm.GetWalletUsageStats(c.Request.Context(), apiKey, policyID, address, policy.Limits.TimeWindowHours)
	if err != nil {
		log.Error("Failed to get wallet usage stats", "policy_id", policyID, "address", address, "time_window_hours", policy.Limits.TimeWindowHours, "policy_name", policy.PolicyName, "error", err)
		types.SendRESTError(c, types.InternalErrorCode, "Failed to get usage stats")
		return
	}

	// Convert wei to ETH for display
	weiPerEth := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	currentUsageEth := new(big.Float).Quo(new(big.Float).SetInt(big.NewInt(usageStats.TotalWeiAmount)), new(big.Float).SetInt(weiPerEth))

	// Calculate remaining ETH
	remainingEth := new(big.Float).Sub(maxEthLimit, currentUsageEth)
	if remainingEth.Sign() < 0 {
		remainingEth = big.NewFloat(0)
	}

	result := map[string]interface{}{
		"address":           address,
		"policy_id":         policyID,
		"time_window_hours": policy.Limits.TimeWindowHours,
		"usage": map[string]interface{}{
			"transaction_count": usageStats.TransactionCount,
			"eth_used":          currentUsageEth.String(),
			"max_transactions":  policy.Limits.MaxTransactionsPerWalletPerWindow,
			"max_eth":           policy.Limits.MaxEthPerWalletPerWindow,
		},
		"remaining": map[string]interface{}{
			"transaction_quota": max(0, policy.Limits.MaxTransactionsPerWalletPerWindow-usageStats.TransactionCount),
			"eth_quota":         remainingEth.String(),
		},
	}

	// Check rate limiting conditions
	rateLimited := false
	rateLimitReason := ""

	// Check transaction count limit
	if usageStats.TransactionCount >= policy.Limits.MaxTransactionsPerWalletPerWindow {
		rateLimited = true
		rateLimitReason = "Transaction count limit exceeded"
	}

	// Check ETH limit
	if currentUsageEth.Cmp(maxEthLimit) >= 0 {
		if rateLimited {
			rateLimitReason = "Both transaction count and ETH limit exceeded"
		} else {
			rateLimited = true
			rateLimitReason = "ETH limit exceeded"
		}
	}

	result["rate_limited"] = rateLimited
	if rateLimited {
		result["rate_limit_reason"] = rateLimitReason
		if usageStats.EarliestTransactionTime != nil {
			result["earliest_transaction_time"] = usageStats.EarliestTransactionTime.Format(time.RFC3339)
		}
	}

	types.SendRESTSuccess(c, result)
}

// max returns the maximum of two int64 values
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
