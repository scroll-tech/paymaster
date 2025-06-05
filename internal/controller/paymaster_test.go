package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/orm"
	"github.com/scroll-tech/paymaster/internal/types"
)

func init() {
	handler := log.StreamHandler(os.Stderr, log.TerminalFormat(true))
	handler = log.LvlFilterHandler(log.LvlDebug, handler)
	log.Root().SetHandler(handler)
}

const (
	testSenderAddress1 = "0x1234567890123456789012345678901234567890"
	testSenderAddress2 = "0x0987654321098765432109876543210987654321"
)

func setupPaymasterTestRouter(db *gorm.DB) *gin.Engine {
	cfg := &config.Config{
		APIKey:             "test-api-key",
		SignerPrivateKey:   "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // test private key
		PaymasterAddressV7: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		ChainID:            534352, // Scroll mainnet (L2)
		USDTAddress:        common.HexToAddress("0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4"),
		EthereumRPCURLs: []string{
			"https://eth.llamarpc.com",
			"https://rpc.ankr.com/eth",
			"https://ethereum.publicnode.com",
		},
	}

	paymasterController := NewPaymasterController(cfg, db)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Mock authentication middleware
	router.Use(func(c *gin.Context) {
		c.Set("api_key", "test-api-key")
		c.Next()
	})

	// Setup routes
	router.POST("/paymaster", func(c *gin.Context) {
		var req types.PaymasterJSONRPCRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			types.SendError(c, nil, types.InvalidRequestCode, "Invalid JSON-RPC request")
			return
		}

		apiKey := c.GetString("api_key")
		paymasterController.handlePaymasterMethod(c, req, apiKey)
	})

	return router
}

func createTestPolicy(t *testing.T, db *gorm.DB, maxEth string, timeWindowHours int) {
	policyOrm := orm.NewPolicy(db)
	policy := &orm.Policy{
		APIKey:     "test-api-key",
		PolicyID:   1,
		PolicyName: "Test Policy",
		Limits: orm.PolicyLimits{
			MaxEthPerWalletPerWindow: maxEth,
			TimeWindowHours:          timeWindowHours,
		},
	}

	err := policyOrm.Create(context.Background(), policy)
	require.NoError(t, err)
}

func makePaymasterRequest(t *testing.T, router *gin.Engine, method string, userOp map[string]interface{}, policyID int64) *httptest.ResponseRecorder {
	reqBody := types.PaymasterJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		ID:      1,
	}

	params := []interface{}{
		userOp,
		"0x0000000071727De22E5E9d8BAf0edAc6f37da032", // EntryPoint v0.7
		"0x82750", // Chain ID (Scroll mainnet)
		map[string]interface{}{
			"policy_id": policyID,
			"token":     "", // Empty for ETH
		},
	}

	paramBytes, err := json.Marshal(params)
	require.NoError(t, err)
	reqBody.Params = json.RawMessage(paramBytes)

	jsonBytes, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/paymaster", bytes.NewBuffer(jsonBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func createTestUserOp(sender string, nonce int64) map[string]interface{} {
	return map[string]interface{}{
		"sender":               sender,
		"nonce":                hexutil.EncodeBig(big.NewInt(nonce)),
		"initCode":             "0x",
		"callData":             "0x",
		"verificationGasLimit": hexutil.EncodeBig(big.NewInt(100000)),
		"callGasLimit":         hexutil.EncodeBig(big.NewInt(200000)),
		"preVerificationGas":   hexutil.EncodeBig(big.NewInt(50000)),
		"maxFeePerGas":         hexutil.EncodeBig(big.NewInt(2000000000)), // 2 gwei
		"maxPriorityFeePerGas": hexutil.EncodeBig(big.NewInt(1000000000)), // 1 gwei
		"paymasterAndData":     "0x",
		"signature":            "0x",
	}
}

func TestPaymasterController_QuotaLimiting(t *testing.T) {
	t.Run("GetPaymasterStubData_WithinQuota", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24) // 1 ETH limit, 24 hours window

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		require.NotNil(t, resp.Result)

		result := resp.Result.(map[string]interface{})
		assert.NotEmpty(t, result["paymaster"])
		assert.NotEmpty(t, result["paymasterData"])
		assert.NotEmpty(t, result["paymasterVerificationGasLimit"])
		assert.NotEmpty(t, result["paymasterPostOpGasLimit"])
	})

	t.Run("GetPaymasterData_WithinQuota", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24) // 1 ETH limit, 24 hours window

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		require.NotNil(t, resp.Result)

		result := resp.Result.(map[string]interface{})
		assert.NotEmpty(t, result["paymaster"])
		assert.NotEmpty(t, result["paymasterData"])
	})

	t.Run("QuotaExceeded_MultipleOperations", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "0.001", 24)

		// First operation should succeed
		userOp1 := createTestUserOp(testSenderAddress1, 1)
		w1 := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp1, 1)
		assert.Equal(t, http.StatusOK, w1.Code)

		var resp1 types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w1.Body.Bytes(), &resp1)
		require.NoError(t, err)
		assert.Nil(t, resp1.Error)

		// Second operation should exceed quota
		userOp2 := createTestUserOp(testSenderAddress1, 2)
		w2 := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp2, 1)
		assert.Equal(t, http.StatusOK, w2.Code)

		var resp2 types.PaymasterJSONRPCResponse
		err = json.Unmarshal(w2.Body.Bytes(), &resp2)
		require.NoError(t, err)

		assert.NotNil(t, resp2.Error)
		assert.Equal(t, types.QuotaExceededErrorCode, resp2.Error.Code)
		assert.Contains(t, resp2.Error.Message, "Quota exceeded")
	})

	t.Run("QuotaCheck_DifferentWallets", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "0.001", 24)

		// First wallet operation
		userOp1 := createTestUserOp(testSenderAddress1, 1)
		w1 := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp1, 1)
		assert.Equal(t, http.StatusOK, w1.Code)

		var resp1 types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w1.Body.Bytes(), &resp1)
		require.NoError(t, err)
		assert.Nil(t, resp1.Error)

		// Second wallet operation should succeed (different wallet)
		userOp2 := createTestUserOp(testSenderAddress2, 1)
		w2 := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp2, 1)
		assert.Equal(t, http.StatusOK, w2.Code)

		var resp2 types.PaymasterJSONRPCResponse
		err = json.Unmarshal(w2.Body.Bytes(), &resp2)
		require.NoError(t, err)
		assert.Nil(t, resp2.Error)
	})

	t.Run("PolicyNotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		// No policy created

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 999)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.QuotaExceededErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Quota exceeded")
	})

	t.Run("UpdateOperationStatus_StubToFinal", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24) // 1 ETH limit, 24 hours window

		userOp := createTestUserOp(testSenderAddress1, 1)

		// First get stub data
		w1 := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1)
		assert.Equal(t, http.StatusOK, w1.Code)

		var resp1 types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w1.Body.Bytes(), &resp1)
		require.NoError(t, err)
		assert.Nil(t, resp1.Error)

		// Then get final paymaster data (should update the same record)
		w2 := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1)
		assert.Equal(t, http.StatusOK, w2.Code)

		var resp2 types.PaymasterJSONRPCResponse
		err = json.Unmarshal(w2.Body.Bytes(), &resp2)
		require.NoError(t, err)
		assert.Nil(t, resp2.Error)

		// Verify the record in database
		var operation orm.UserOperation
		err = db.Where("api_key = ?", "test-api-key").
			Where("policy_id = ?", 1).
			Where("sender = ?", testSenderAddress1).
			Where("nonce = ?", 1).
			First(&operation).Error
		require.NoError(t, err)
		assert.Equal(t, orm.UserOperationStatusPaymasterDataProvided, operation.Status)
	})
}

func TestPaymasterController_QuotaLimiting_EdgeCases(t *testing.T) {
	t.Run("ExactQuotaLimit", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)

		// Calculate expected gas cost for the test userOp
		// verificationGas (100000) + callGas (200000) + preVerificationGas (50000) + paymasterVerificationGas (25000) + paymasterPostOpGas (5000) = 380000
		// 380000 * 2 gwei = 760,000,000,000,000 wei = 0.00076 ETH
		createTestPolicy(t, db, "0.00076", 24) // Exact limit

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Nil(t, resp.Error)
	})

	t.Run("JustOverQuotaLimit", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)

		// Set limit slightly below expected cost
		createTestPolicy(t, db, "0.00075", 24) // Just below limit

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.QuotaExceededErrorCode, resp.Error.Code)
	})

	t.Run("TimeWindowExpiry", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "0.001", 1) // 1 hour window

		// Create an old operation (simulate it's from 2 hours ago)
		userOpOrm := orm.NewUserOperation(db)
		oldTime := time.Now().UTC().Add(-2 * time.Hour)

		oldOp := &orm.UserOperation{
			APIKey:    "test-api-key",
			PolicyID:  1,
			Sender:    testSenderAddress1,
			Nonce:     1,
			WeiAmount: 500000000000000, // 0.0005 ETH
			Status:    orm.UserOperationStatusPaymasterDataProvided,
		}
		err := userOpOrm.CreateOrUpdate(context.Background(), oldOp)
		require.NoError(t, err)

		err = db.Model(&orm.UserOperation{}).
			Where("api_key = ?", "test-api-key").
			Where("sender = ?", testSenderAddress1).
			Where("nonce = ?", 1).
			Updates(map[string]interface{}{
				"created_at": oldTime,
				"updated_at": oldTime,
			}).Error
		require.NoError(t, err)

		// New operation should succeed because old one is outside time window
		userOp := createTestUserOp(testSenderAddress1, 2)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Nil(t, resp.Error)
	})
}

func TestPaymasterController_TokenPayments(t *testing.T) {
	t.Run("USDTPayment_NoQuotaCheck", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "0.000000000000000001", 24) // Very low ETH limit

		userOp := createTestUserOp(testSenderAddress1, 1)

		// Make request with USDT token
		reqBody := types.PaymasterJSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "pm_getPaymasterStubData",
			ID:      1,
		}

		params := []interface{}{
			userOp,
			"0x0000000071727De22E5E9d8BAf0edAc6f37da032", // EntryPoint v0.7
			"0x82750", // Chain ID (Scroll mainnet)
			map[string]interface{}{
				"policy_id": 1,
				"token":     "0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4", // USDT address
			},
		}

		paramBytes, err := json.Marshal(params)
		require.NoError(t, err)
		reqBody.Params = json.RawMessage(paramBytes)

		jsonBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/paymaster", bytes.NewBuffer(jsonBytes))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		// Should succeed even with low ETH quota because USDT payments don't check ETH quota
		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)
	})
}
