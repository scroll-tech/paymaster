// Package controller_test provides integration tests for the admin controller.
package controller

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/orm"
	"github.com/scroll-tech/paymaster/internal/types"
)

func setupTestDB(t *testing.T) *gorm.DB {
	// Use in-memory SQLite database for testing
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Info,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: newLogger,
	})
	require.NoError(t, err)

	// Auto migrate table schemas
	err = db.AutoMigrate(&orm.Policy{}, &orm.UserOperation{})
	require.NoError(t, err)

	return db
}

func setupTestRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		APIKey: "test-api-key",
	}

	adminController := NewAdminController(cfg, db)

	router := gin.New()

	// Mock authentication middleware
	router.Use(func(c *gin.Context) {
		c.Set("api_key", "test-api-key")
		c.Next()
	})

	// Setup routes
	router.POST("/admin", func(c *gin.Context) {
		var req types.PaymasterJSONRPCRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			types.SendError(c, nil, types.InvalidRequestCode, "Invalid JSON-RPC request")
			return
		}

		apiKey := c.GetString("api_key")
		adminController.handleAdminMethod(c, req, apiKey)
	})

	return router
}

func makeRequest(t *testing.T, router *gin.Engine, method string, params interface{}) *httptest.ResponseRecorder {
	reqBody := types.PaymasterJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		ID:      1,
	}

	if params != nil {
		paramBytes, err := json.Marshal(params)
		require.NoError(t, err)
		reqBody.Params = json.RawMessage(paramBytes)
	}

	jsonBytes, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/admin", bytes.NewBuffer(jsonBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func TestAdminController_Integration(t *testing.T) {
	t.Run("CreatePolicy_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   "1",
			"policy_name": "Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)

		result := resp.Result.(map[string]interface{})
		assert.True(t, result["success"].(bool))
		assert.Equal(t, "Policy created successfully", result["message"])
	})

	t.Run("GetPolicyByID_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   "10",
			"policy_name": "Get Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.5",
				"time_window_hours":             48,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Then get the policy
		getParams := map[string]interface{}{
			"policy_id": "10",
		}

		w = makeRequest(t, router, "pm_getPolicyByID", getParams)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)

		result := resp.Result.(map[string]interface{})
		assert.Equal(t, "10", result["policy_id"])
		assert.Equal(t, "Get Test Policy", result["policy_name"])

		limits := result["limits"].(map[string]interface{})
		assert.Equal(t, "0.5", limits["max_eth_per_wallet_per_window"])
		assert.Equal(t, float64(48), limits["time_window_hours"])
	})

	t.Run("ListPolicies_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// Create several policies
		policies := []map[string]interface{}{
			{
				"policy_id":   "20",
				"policy_name": "List Test Policy 1",
				"limits": map[string]interface{}{
					"max_eth_per_wallet_per_window": "0.1",
					"time_window_hours":             24,
				},
			},
			{
				"policy_id":   "21",
				"policy_name": "List Test Policy 2",
				"limits": map[string]interface{}{
					"max_eth_per_wallet_per_window": "0.2",
					"time_window_hours":             48,
				},
			},
		}

		for _, policy := range policies {
			w := makeRequest(t, router, "pm_createPolicy", policy)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// List all policies
		w := makeRequest(t, router, "pm_listPolicies", nil)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)

		result := resp.Result.([]interface{})
		assert.GreaterOrEqual(t, len(result), 2)

		// Find our test policies in the sorted list
		policy1 := result[0].(map[string]interface{})
		policy2 := result[1].(map[string]interface{})

		// Verify Policy 1 (ID: 20)
		assert.NotNil(t, policy1, "Policy with ID 20 should exist")
		assert.Equal(t, "20", policy1["policy_id"])
		assert.Equal(t, "List Test Policy 1", policy1["policy_name"])
		assert.NotNil(t, policy1["created_at"])
		assert.NotNil(t, policy1["updated_at"])

		limits1 := policy1["limits"].(map[string]interface{})
		assert.Equal(t, "0.1", limits1["max_eth_per_wallet_per_window"])
		assert.Equal(t, float64(24), limits1["time_window_hours"])

		// Verify Policy 2 (ID: 21)
		assert.NotNil(t, policy2, "Policy with ID 21 should exist")
		assert.Equal(t, "21", policy2["policy_id"])
		assert.Equal(t, "List Test Policy 2", policy2["policy_name"])
		assert.NotNil(t, policy2["created_at"])
		assert.NotNil(t, policy2["updated_at"])

		limits2 := policy2["limits"].(map[string]interface{})
		assert.Equal(t, "0.2", limits2["max_eth_per_wallet_per_window"])
		assert.Equal(t, float64(48), limits2["time_window_hours"])

		// Verify that all policies in the list have the required fields
		for _, item := range result {
			policy := item.(map[string]interface{})

			// Check required fields exist and have correct types
			assert.IsType(t, "", policy["policy_id"])
			assert.IsType(t, "", policy["policy_name"])
			assert.IsType(t, map[string]interface{}{}, policy["limits"])
			assert.IsType(t, "", policy["created_at"])
			assert.IsType(t, "", policy["updated_at"])

			// Check limits structure
			limits := policy["limits"].(map[string]interface{})
			assert.IsType(t, "", limits["max_eth_per_wallet_per_window"])
			assert.IsType(t, float64(0), limits["time_window_hours"])
		}
	})

	t.Run("UpdatePolicy_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   "30",
			"policy_name": "Update Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Update the policy
		updateParams := map[string]interface{}{
			"policy_id":   "30",
			"policy_name": "Updated Policy Name",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.2",
				"time_window_hours":             48,
			},
		}

		w = makeRequest(t, router, "pm_updatePolicy", updateParams)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)

		result := resp.Result.(map[string]interface{})
		assert.True(t, result["success"].(bool))
		assert.Equal(t, "Policy updated successfully", result["message"])

		// Verify the update took effect
		getParams := map[string]interface{}{
			"policy_id": "30",
		}

		w = makeRequest(t, router, "pm_getPolicyByID", getParams)
		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		result = resp.Result.(map[string]interface{})
		assert.Equal(t, "Updated Policy Name", result["policy_name"])

		limits := result["limits"].(map[string]interface{})
		assert.Equal(t, "0.2", limits["max_eth_per_wallet_per_window"])
		assert.Equal(t, float64(48), limits["time_window_hours"])
	})

	t.Run("DeletePolicy_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   "40",
			"policy_name": "Delete Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Delete the policy
		deleteParams := map[string]interface{}{
			"policy_id": "40",
		}

		w = makeRequest(t, router, "pm_deletePolicy", deleteParams)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)

		result := resp.Result.(map[string]interface{})
		assert.True(t, result["success"].(bool))
		assert.Equal(t, "Policy deleted successfully", result["message"])

		// Verify the policy was deleted
		getParams := map[string]interface{}{
			"policy_id": "40",
		}

		w = makeRequest(t, router, "pm_getPolicyByID", getParams)

		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyNotFoundCode, resp.Error.Code)
	})
}

func TestValidatePolicyLimits(t *testing.T) {
	ac := NewAdminController(&config.Config{}, nil)

	t.Run("ValidLimits", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1.5",
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})

	t.Run("MinimalValidLimits", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "0.000000000000000001", // 1 wei
			TimeWindowHours:          1,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})

	t.Run("MaximalValidLimits", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1000.123456789012345678", // 18 decimal places
			TimeWindowHours:          8760,                      // 1 year
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})

	t.Run("ExactWeiPrecision", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "0.000000000000000123", // Exactly representable in wei
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})
}

func TestAdminController_Integration_InvalidCases(t *testing.T) {
	t.Run("CreatePolicy_InvalidParams", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// Missing policy_id
		params := map[string]interface{}{
			"policy_name": "Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "policy_id is required")
	})

	t.Run("CreatePolicy_MissingPolicyName", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": "100",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "policy_name is required")
	})

	t.Run("CreatePolicy_InvalidPolicyIDFormat", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   "invalid_id",
			"policy_name": "Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Invalid policy_id format")
	})

	t.Run("CreatePolicy_ValidationError", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   "101",
			"policy_name": "Invalid Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0", // Invalid: must be > 0
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyValidationErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "must be positive")
	})

	t.Run("GetPolicyByID_NotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": "999",
		}

		w := makeRequest(t, router, "pm_getPolicyByID", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyNotFoundCode, resp.Error.Code)
		assert.Equal(t, "Policy not found", resp.Error.Message)
	})

	t.Run("GetPolicyByID_MissingPolicyID", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{}

		w := makeRequest(t, router, "pm_getPolicyByID", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "policy_id is required")
	})

	t.Run("GetPolicyByID_InvalidPolicyIDFormat", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": "invalid_id",
		}

		w := makeRequest(t, router, "pm_getPolicyByID", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Invalid policy_id format")
	})

	t.Run("UpdatePolicy_NotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   "999",
			"policy_name": "Non-existent Policy",
		}

		w := makeRequest(t, router, "pm_updatePolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyNotFoundCode, resp.Error.Code)
	})

	t.Run("UpdatePolicy_NoUpdateParams", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   "102",
			"policy_name": "Test Policy for Update",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Try to update without any parameters
		updateParams := map[string]interface{}{
			"policy_id": "102",
		}

		w = makeRequest(t, router, "pm_updatePolicy", updateParams)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "No update parameters provided")
	})

	t.Run("UpdatePolicy_ValidationError", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   "103",
			"policy_name": "Test Policy for Update",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Try to update with invalid limits
		updateParams := map[string]interface{}{
			"policy_id": "103",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "-1", // Invalid: negative value
				"time_window_hours":             24,
			},
		}

		w = makeRequest(t, router, "pm_updatePolicy", updateParams)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyValidationErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "must be positive")
	})

	t.Run("DeletePolicy_NotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": "999",
		}

		w := makeRequest(t, router, "pm_deletePolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyNotFoundCode, resp.Error.Code)
	})

	t.Run("DeletePolicy_MissingPolicyID", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{}

		w := makeRequest(t, router, "pm_deletePolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "policy_id is required")
	})

	t.Run("InvalidMethod", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		w := makeRequest(t, router, "pm_invalidMethod", nil)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.MethodNotFoundCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Method not found")
	})

	t.Run("InvalidJSONStructure", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// Send malformed JSON
		req := httptest.NewRequest(http.MethodPost, "/admin", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidRequestCode, resp.Error.Code)
	})
}

func TestValidatePolicyLimits_InvalidCases(t *testing.T) {
	ac := NewAdminController(&config.Config{}, nil)

	t.Run("NilLimits", func(t *testing.T) {
		err := ac.validatePolicyLimits(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("EmptyMaxEth", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "",
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is required")
	})

	t.Run("InvalidMaxEthFormat", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "invalid",
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid max_eth_per_wallet_per_window format")
	})

	t.Run("ZeroMaxEth", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "0",
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("NegativeMaxEth", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "-1",
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("TooManyDecimals", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1.0000000000000000001", // 19 decimal places
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too many decimal places")
	})

	t.Run("BelowMinimumWei", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			// Use a value that has <=18 decimal places but is less than 1 wei
			MaxEthPerWalletPerWindow: "0.000000000000000000", // 0 wei, 18 decimal places
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		// This will trigger the "must be positive" check since it's 0
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("ZeroTimeWindow", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1.0",
			TimeWindowHours:          0,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "time_window_hours must be positive")
	})

	t.Run("NegativeTimeWindow", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1.0",
			TimeWindowHours:          -1,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "time_window_hours must be positive")
	})

	t.Run("ExcessiveTimeWindow", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1.0",
			TimeWindowHours:          9000,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed 8760 hours")
	})

	t.Run("SpecialFloatValues", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "NaN",
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err, "Expected error for input: %s", "NaN")
		assert.Contains(t, err.Error(), "invalid max_eth_per_wallet_per_window format", "Expected format error for input: NaN")
	})

	t.Run("ScientificNotationValid", func(t *testing.T) {
		// Test valid scientific notation
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1e-18", // 1 wei in ETH
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err) // This should be valid
	})

	t.Run("ScientificNotationInvalid", func(t *testing.T) {
		// Test invalid scientific notation with too much precision
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow: "1e-19", // Less than 1 wei
			TimeWindowHours:          24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too many decimal places")
	})
}
