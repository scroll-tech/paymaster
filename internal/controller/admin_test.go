package controller

import (
	"bytes"
	"context"
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
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/orm"
	"github.com/scroll-tech/paymaster/internal/types"
)

func setupTestDB(t *testing.T) *gorm.DB {
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
		),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, postgresContainer.Terminate(ctx))
	})

	dsn, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Info,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	var db *gorm.DB
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = gorm.Open(pgdriver.Open(dsn), &gorm.Config{
			Logger: newLogger,
		})

		if err == nil {
			sqlDB, pingErr := db.DB()
			if pingErr == nil {
				pingErr = sqlDB.Ping()
				if pingErr == nil {
					break
				}
			}
			err = pingErr
		}

		if i < maxRetries-1 {
			t.Logf("Database connection attempt %d/%d failed: %v, retrying...", i+1, maxRetries, err)
			time.Sleep(500 * time.Millisecond)
		}
	}
	require.NoError(t, err, "Failed to connect to database after %d retries", maxRetries)

	// Auto migrate table schemas
	err = db.AutoMigrate(&orm.Policy{}, &orm.UserOperation{})
	require.NoError(t, err)

	return db
}

func setupTestRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		APIKeys: []string{"test-api-key"},
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
			"policy_id":   1,
			"policy_name": "Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
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
			"policy_id":   10,
			"policy_name": "Get Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.5",
				"max_transactions_per_wallet_per_window": 200,
				"time_window_hours":                      48,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Then get the policy
		getParams := map[string]interface{}{
			"policy_id": 10,
		}

		w = makeRequest(t, router, "pm_getPolicyByID", getParams)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)

		var policy types.PolicyResponse
		resultBytes, err := json.Marshal(resp.Result)
		require.NoError(t, err)
		err = json.Unmarshal(resultBytes, &policy)
		require.NoError(t, err)

		assert.Equal(t, int64(10), policy.PolicyID)
		assert.Equal(t, "Get Test Policy", policy.PolicyName)
		assert.Equal(t, "0.5", policy.Limits.MaxEthPerWalletPerWindow)
		assert.Equal(t, int64(200), policy.Limits.MaxTransactionsPerWalletPerWindow)
		assert.Equal(t, int(48), policy.Limits.TimeWindowHours)
	})

	t.Run("ListPolicies_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// Create several policies
		policies := []map[string]interface{}{
			{
				"policy_id":   20,
				"policy_name": "List Test Policy 1",
				"limits": map[string]interface{}{
					"max_eth_per_wallet_per_window":          "0.1",
					"max_transactions_per_wallet_per_window": 50,
					"time_window_hours":                      24,
				},
			},
			{
				"policy_id":   21,
				"policy_name": "List Test Policy 2",
				"limits": map[string]interface{}{
					"max_eth_per_wallet_per_window":          "0.2",
					"max_transactions_per_wallet_per_window": 150,
					"time_window_hours":                      48,
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

		var policyList []types.PolicyResponse
		resultBytes, err := json.Marshal(resp.Result)
		require.NoError(t, err)
		err = json.Unmarshal(resultBytes, &policyList)
		require.NoError(t, err)

		assert.Equal(t, 2, len(policyList))

		// Policies are returned in ascending order by policy_id
		policy1 := policyList[0]
		policy2 := policyList[1]

		// Verify Policy 1 (ID: 20)
		assert.NotNil(t, policy1, "Policy with ID 20 should exist")
		assert.Equal(t, int64(20), policy1.PolicyID)
		assert.Equal(t, "List Test Policy 1", policy1.PolicyName)
		assert.NotEmpty(t, policy1.CreatedAt)
		assert.NotEmpty(t, policy1.UpdatedAt)
		assert.Equal(t, "0.1", policy1.Limits.MaxEthPerWalletPerWindow)
		assert.Equal(t, int64(50), policy1.Limits.MaxTransactionsPerWalletPerWindow)
		assert.Equal(t, int(24), policy1.Limits.TimeWindowHours)

		// Verify Policy 2 (ID: 21)
		assert.NotNil(t, policy2, "Policy with ID 21 should exist")
		assert.Equal(t, int64(21), policy2.PolicyID)
		assert.Equal(t, "List Test Policy 2", policy2.PolicyName)
		assert.NotEmpty(t, policy2.CreatedAt)
		assert.NotEmpty(t, policy2.UpdatedAt)
		assert.Equal(t, "0.2", policy2.Limits.MaxEthPerWalletPerWindow)
		assert.Equal(t, int64(150), policy2.Limits.MaxTransactionsPerWalletPerWindow)
		assert.Equal(t, int(48), policy2.Limits.TimeWindowHours)
	})

	t.Run("UpdatePolicy_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   30,
			"policy_name": "Update Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Update the policy
		updateParams := map[string]interface{}{
			"policy_id":   30,
			"policy_name": "Updated Policy Name",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.2",
				"max_transactions_per_wallet_per_window": 250,
				"time_window_hours":                      48,
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
			"policy_id": 30,
		}

		w = makeRequest(t, router, "pm_getPolicyByID", getParams)
		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		var policy types.PolicyResponse
		resultBytes, err := json.Marshal(resp.Result)
		require.NoError(t, err)
		err = json.Unmarshal(resultBytes, &policy)
		require.NoError(t, err)

		assert.Equal(t, "Updated Policy Name", policy.PolicyName)
		assert.Equal(t, "0.2", policy.Limits.MaxEthPerWalletPerWindow)
		assert.Equal(t, int64(250), policy.Limits.MaxTransactionsPerWalletPerWindow)
		assert.Equal(t, int(48), policy.Limits.TimeWindowHours)
	})

	t.Run("DeletePolicy_Success", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		// First create a policy
		createParams := map[string]interface{}{
			"policy_id":   40,
			"policy_name": "Delete Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Delete the policy
		deleteParams := map[string]interface{}{
			"policy_id": 40,
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
			"policy_id": 40,
		}

		w = makeRequest(t, router, "pm_getPolicyByID", getParams)
		assert.Equal(t, http.StatusOK, w.Code)

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
			MaxEthPerWalletPerWindow:          "1.5",
			MaxTransactionsPerWalletPerWindow: 1000,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})

	t.Run("MinimalValidLimits", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "0.000000000000000001", // 1 wei
			MaxTransactionsPerWalletPerWindow: 1,
			TimeWindowHours:                   1,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})

	t.Run("MaximalValidLimits", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1000.123456789012345678", // 18 decimal places
			MaxTransactionsPerWalletPerWindow: 1000000,                   // 1 million
			TimeWindowHours:                   8760,                      // 1 year
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err)
	})

	t.Run("ExactWeiPrecision", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "0.000000000000000123", // Exactly representable in wei
			MaxTransactionsPerWalletPerWindow: 50,
			TimeWindowHours:                   24,
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
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
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
			"policy_id": 100,
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
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

	t.Run("CreatePolicy_MissingTransactionLimit", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   101,
			"policy_name": "Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window": "0.1",
				"time_window_hours":             24,
				// Missing max_transactions_per_wallet_per_window
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyValidationErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "max_transactions_per_wallet_per_window must be positive")
	})

	t.Run("CreatePolicy_NegativePolicyID", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   -1,
			"policy_name": "Test Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "policy_id must be positive")
	})

	t.Run("CreatePolicy_ValidationError_ZeroEth", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   102,
			"policy_name": "Invalid Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0", // Invalid: must be > 0
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
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

	t.Run("CreatePolicy_ValidationError_ZeroTransactions", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   103,
			"policy_name": "Invalid Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 0, // Invalid: must be > 0
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyValidationErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "max_transactions_per_wallet_per_window must be positive")
	})

	t.Run("CreatePolicy_ValidationError_NegativeTransactions", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   104,
			"policy_name": "Invalid Policy",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": -10, // Invalid: negative
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyValidationErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "max_transactions_per_wallet_per_window must be positive")
	})

	t.Run("GetPolicyByID_NotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": 999,
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

	t.Run("GetPolicyByID_NegativePolicyID", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": -1,
		}

		w := makeRequest(t, router, "pm_getPolicyByID", params)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "policy_id must be positive")
	})

	t.Run("UpdatePolicy_NotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id":   999,
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
			"policy_id":   105,
			"policy_name": "Test Policy for Update",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Try to update without any parameters
		updateParams := map[string]interface{}{
			"policy_id": 105,
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
			"policy_id":   106,
			"policy_name": "Test Policy for Update",
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "0.1",
				"max_transactions_per_wallet_per_window": 100,
				"time_window_hours":                      24,
			},
		}

		w := makeRequest(t, router, "pm_createPolicy", createParams)
		assert.Equal(t, http.StatusOK, w.Code)

		// Try to update with invalid limits
		updateParams := map[string]interface{}{
			"policy_id": 106,
			"limits": map[string]interface{}{
				"max_eth_per_wallet_per_window":          "-1", // Invalid: negative value
				"max_transactions_per_wallet_per_window": -5,   // Invalid: negative value
				"time_window_hours":                      24,
			},
		}

		w = makeRequest(t, router, "pm_updatePolicy", updateParams)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.PolicyValidationErrorCode, resp.Error.Code)
		// Should contain error about either eth or transaction limit being invalid
		assert.True(t,
			assert.ObjectsAreEqual(true, resp.Error.Message) ||
				assert.Contains(t, resp.Error.Message, "must be positive") ||
				assert.Contains(t, resp.Error.Message, "max_transactions_per_wallet_per_window must be positive"))
	})

	t.Run("DeletePolicy_NotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupTestRouter(db)

		params := map[string]interface{}{
			"policy_id": 999,
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
			MaxEthPerWalletPerWindow:          "",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is required")
	})

	t.Run("InvalidMaxEthFormat", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "invalid",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid max_eth_per_wallet_per_window format")
	})

	t.Run("ZeroMaxEth", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "0",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("NegativeMaxEth", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "-1",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("ZeroMaxTransactions", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0",
			MaxTransactionsPerWalletPerWindow: 0,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max_transactions_per_wallet_per_window must be positive")
	})

	t.Run("NegativeMaxTransactions", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0",
			MaxTransactionsPerWalletPerWindow: -10,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max_transactions_per_wallet_per_window must be positive")
	})

	t.Run("TooManyDecimals", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0000000000000000001", // 19 decimal places
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too many decimal places")
	})

	t.Run("BelowMinimumWei", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "0.000000000000000000", // 0 wei, 18 decimal places
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		// This will trigger the "must be positive" check since it's 0
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("ZeroTimeWindow", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   0,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "time_window_hours must be positive")
	})

	t.Run("NegativeTimeWindow", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   -1,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "time_window_hours must be positive")
	})

	t.Run("ExcessiveTimeWindow", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   9000,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed 8760 hours")
	})

	t.Run("ExcessiveTransactionLimit", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1.0",
			MaxTransactionsPerWalletPerWindow: 1000001, // Over 1 million
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed 1000000")
	})

	t.Run("SpecialFloatValues", func(t *testing.T) {
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "NaN",
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err, "Expected error for input: %s", "NaN")
		assert.Contains(t, err.Error(), "invalid max_eth_per_wallet_per_window format", "Expected format error for input: NaN")
	})

	t.Run("ScientificNotationValid", func(t *testing.T) {
		// Test valid scientific notation
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1e-18", // 1 wei in ETH
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.NoError(t, err) // This should be valid
	})

	t.Run("ScientificNotationInvalid", func(t *testing.T) {
		// Test invalid scientific notation with too much precision
		limits := &orm.PolicyLimits{
			MaxEthPerWalletPerWindow:          "1e-19", // Less than 1 wei
			MaxTransactionsPerWalletPerWindow: 100,
			TimeWindowHours:                   24,
		}

		err := ac.validatePolicyLimits(limits)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too many decimal places")
	})
}
