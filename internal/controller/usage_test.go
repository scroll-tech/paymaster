package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/scroll-tech/paymaster/internal/config"
)

func setupUsageStatsTestRouter(db *gorm.DB) (*gin.Engine, *PaymasterController) {
	cfg := &config.Config{
		APIKeys:          []string{"test-api-key"},
		SignerPrivateKey: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		ChainID:          534352,
	}

	paymasterController := NewPaymasterController(cfg, db)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Mock authentication middleware
	router.Use(func(c *gin.Context) {
		c.Set("api_key", "test-api-key")
		c.Next()
	})

	// Setup usage stats route - GET /api/usage/:address/:policy_id
	router.GET("/api/usage/:address/:policy_id", func(c *gin.Context) {
		apiKey := c.GetString("api_key")
		address := c.Param("address")
		policyIDStr := c.Param("policy_id")

		policyID, err := strconv.ParseInt(policyIDStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy_id"})
			return
		}

		paymasterController.GetUsageStats(c, apiKey, address, policyID)
	})

	return router, paymasterController
}

func makeUsageStatsRequest(router *gin.Engine, address string, policyID int64) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/usage/%s/%d", address, policyID), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestGetUsageStats_WithinRateLimit(t *testing.T) {
	db := setupTestDB(t)
	router, _ := setupUsageStatsTestRouter(db)

	// Create policy with reasonable limits
	createTestPolicy(t, db, "1.0", 24, 10) // 1 ETH limit, 10 transactions, 24 hours

	// Create some usage data within limits
	createTestUsageStats(t, db, 500000000000000, 3, 1, 1) // 0.0005 ETH, 3 transactions, 1 hour ago

	w := makeUsageStatsRequest(router, testSenderAddress1, 1)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check basic structure
	assert.Equal(t, testSenderAddress1, response["address"])
	assert.Equal(t, float64(1), response["policy_id"])
	assert.Equal(t, float64(24), response["time_window_hours"])

	// Check usage data
	usage := response["usage"].(map[string]interface{})
	assert.Equal(t, float64(3), usage["transaction_count"])
	assert.Equal(t, "0.0005", usage["eth_used"])
	assert.Equal(t, float64(10), usage["max_transactions"])
	assert.Equal(t, "1.0", usage["max_eth"])

	// Check remaining quotas
	remaining := response["remaining"].(map[string]interface{})
	assert.Equal(t, float64(7), remaining["transaction_quota"]) // 10 - 3 = 7
	assert.Equal(t, "0.9995", remaining["eth_quota"])           // 1.0 - 0.0005 = 0.9995

	// Should not be rate limited
	assert.Equal(t, false, response["rate_limited"])
	assert.Nil(t, response["rate_limit_reason"])
}

func TestGetUsageStats_ExceededTransactionLimit(t *testing.T) {
	db := setupTestDB(t)
	router, _ := setupUsageStatsTestRouter(db)

	// Create policy with low transaction limit
	createTestPolicy(t, db, "10.0", 24, 5) // 10 ETH limit, 5 transactions, 24 hours

	// Create usage data that exceeds transaction limit
	createTestUsageStats(t, db, 100000000000000, 6, 1, 1) // 0.0001 ETH, 6 transactions (exceeds 5), 1 hour ago

	w := makeUsageStatsRequest(router, testSenderAddress1, 1)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check usage data
	usage := response["usage"].(map[string]interface{})
	assert.Equal(t, float64(6), usage["transaction_count"]) // Exceeds limit of 5
	assert.Equal(t, float64(5), usage["max_transactions"])

	// Check remaining quotas
	remaining := response["remaining"].(map[string]interface{})
	assert.Equal(t, float64(0), remaining["transaction_quota"]) // max(0, 5-6) = 0

	// Should be rate limited
	assert.Equal(t, true, response["rate_limited"])
	assert.Equal(t, "Transaction count limit exceeded", response["rate_limit_reason"])
	assert.NotNil(t, response["earliest_transaction_time"])

}

func TestGetUsageStats_ExceededETHLimit(t *testing.T) {
	db := setupTestDB(t)
	router, _ := setupUsageStatsTestRouter(db)

	// Create policy with low ETH limit
	createTestPolicy(t, db, "0.001", 24, 100) // 0.001 ETH limit, 100 transactions, 24 hours

	// Create usage data that exceeds ETH limit
	createTestUsageStats(t, db, 2000000000000000, 2, 1, 1) // 0.002 ETH (exceeds 0.001), 2 transactions, 1 hour ago

	w := makeUsageStatsRequest(router, testSenderAddress1, 1)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check usage data
	usage := response["usage"].(map[string]interface{})
	assert.Equal(t, float64(2), usage["transaction_count"])
	assert.Equal(t, "0.002", usage["eth_used"]) // Exceeds limit of 0.001
	assert.Equal(t, "0.001", usage["max_eth"])

	// Check remaining quotas
	remaining := response["remaining"].(map[string]interface{})
	assert.Equal(t, float64(98), remaining["transaction_quota"]) // 100 - 2 = 98
	assert.Equal(t, "0", remaining["eth_quota"])                 // Should be 0 when exceeded

	// Should be rate limited
	assert.Equal(t, true, response["rate_limited"])
	assert.Equal(t, "ETH limit exceeded", response["rate_limit_reason"])
	assert.NotNil(t, response["earliest_transaction_time"])
}
