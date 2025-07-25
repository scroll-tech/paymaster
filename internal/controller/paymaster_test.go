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
	"github.com/ethereum/go-ethereum/crypto"
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

var (
	testUSDTAddress = common.HexToAddress("0xf55bec9cafdbe8730f096aa55dad6d22d44099df")
	testUSDCAddress = common.HexToAddress("0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4")
	testETHAddress  = common.HexToAddress("")
)

func setupPaymasterTestRouter(db *gorm.DB) *gin.Engine {
	cfg := &config.Config{
		APIKeys:            []string{"test-api-key"},
		SignerPrivateKey:   "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // test private key
		PaymasterAddressV7: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		ChainID:            534352, // Scroll mainnet (L2)
		USDTAddress:        common.HexToAddress("0xf55bec9cafdbe8730f096aa55dad6d22d44099df"),
		USDCAddress:        common.HexToAddress("0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4"),
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

func createTestPolicy(t *testing.T, db *gorm.DB, maxEth string, timeWindowHours int, maxTransactions int64) {
	policyOrm := orm.NewPolicy(db)
	policy := &orm.Policy{
		APIKeyHash: crypto.Keccak256Hash([]byte("test-api-key")).Hex(),
		PolicyID:   1,
		PolicyName: "Test Policy",
		Limits: orm.PolicyLimits{
			MaxTransactionsPerWalletPerWindow: maxTransactions,
			MaxEthPerWalletPerWindow:          maxEth,
			TimeWindowHours:                   timeWindowHours,
		},
	}

	err := policyOrm.Create(context.Background(), policy)
	require.NoError(t, err)
}

func makePaymasterRequest(t *testing.T, router *gin.Engine, method string, userOp map[string]interface{}, policyID int64, tokenAddr common.Address) *httptest.ResponseRecorder {
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
			"token":     tokenAddr.Hex(), // Token address of ETH or USDT
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
		"factory":              nil,
		"factoryData":          "",
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

func createTestUserOpWithPaymasterGasLimits(sender string, nonce int64, paymasterVerificationGasLimit, paymasterPostOpGasLimit *big.Int) map[string]interface{} {
	userOp := createTestUserOp(sender, nonce)

	userOp["paymasterVerificationGasLimit"] = hexutil.EncodeBig(paymasterVerificationGasLimit)
	userOp["paymasterPostOpGasLimit"] = hexutil.EncodeBig(paymasterPostOpGasLimit)

	return userOp
}

// Helper function to create test usage stats in database
func createTestUsageStats(t *testing.T, db *gorm.DB, weiAmount int64, txCount int, hoursAgo int, startNonce int64) {
	userOpOrm := orm.NewUserOperation(db)

	apiKeyHash := crypto.Keccak256Hash([]byte("test-api-key")).Hex()
	timestamp := time.Now().UTC().Add(time.Duration(-hoursAgo) * time.Hour)

	for i := 0; i < txCount; i++ {
		userOp := &orm.UserOperation{
			APIKeyHash: apiKeyHash,
			PolicyID:   1,
			Sender:     testSenderAddress1,
			Nonce:      startNonce + int64(i),
			WeiAmount:  weiAmount / int64(txCount), // Distribute amount across transactions
			Status:     orm.UserOperationStatusPaymasterDataProvided,
			CreatedAt:  timestamp,
			UpdatedAt:  timestamp,
		}

		err := userOpOrm.CreateOrUpdate(context.Background(), userOp)
		require.NoError(t, err)

		// Update timestamp to simulate older transactions
		err = db.Model(&orm.UserOperation{}).
			Where("api_key_hash = ?", apiKeyHash).
			Where("sender = ?", testSenderAddress1).
			Where("nonce = ?", startNonce+int64(i)).Error
		require.NoError(t, err)
	}
}

func TestPaymasterController_QuotaLimiting(t *testing.T) {
	t.Run("GetPaymasterStubData_WithinQuota", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24, 10) // 1 ETH limit, 24 hours window

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1, testETHAddress)

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
		createTestPolicy(t, db, "1.0", 24, 10) // 1 ETH limit, 24 hours window

		paymasterVerificationGasLimit, paymasterPostOpGasLimit := calculatePaymasterGasLimits(testETHAddress, testUSDTAddress, testUSDCAddress)
		userOp := createTestUserOpWithPaymasterGasLimits(
			testSenderAddress1,
			1,
			paymasterVerificationGasLimit,
			paymasterPostOpGasLimit,
		)
		w := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1, testETHAddress)

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

	t.Run("PolicyNotFound", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		// No policy created

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 999, testETHAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.QuotaExceededErrorCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Quota exceeded")
	})
}

func TestPaymasterController_QuotaLimiting_EdgeCases(t *testing.T) {
	t.Run("ExactQuotaLimit", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)

		// Calculate expected gas cost for the test userOp
		// verificationGas (100000) + callGas (200000) + preVerificationGas (50000) + paymasterVerificationGas (25000) + paymasterPostOpGas (5000) = 380000
		// 380000 * 2 gwei = 760,000,000,000,000 wei = 0.00076 ETH
		createTestPolicy(t, db, "0.00076", 24, 10) // Exact limit

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1, testETHAddress)

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
		createTestPolicy(t, db, "0.00075", 24, 10) // Just below limit

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1, testETHAddress)

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
		createTestPolicy(t, db, "0.001", 1, 10) // 1 hour window

		// Create old operations outside the time window (2 hours ago)
		createTestUsageStats(t, db, 500000000000000, 1, 2, 0) // 0.0005 ETH, 2 hours ago

		// New operation should succeed because old ones are outside time window
		userOp := createTestUserOp(testSenderAddress1, 10)
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1, testETHAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Nil(t, resp.Error)
	})

	t.Run("UsageStatsAccuracy", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24, 10) // 1 ETH limit, 24 hours window

		// Create multiple transactions with known amounts and different nonces
		createTestUsageStats(t, db, 100000000000000, 2, 1, 1)  // 0.0001 ETH, 2 txs, 1 hour ago, nonces 1-2
		createTestUsageStats(t, db, 200000000000000, 3, 5, 3)  // 0.0002 ETH, 3 txs, 5 hours ago, nonces 3-5
		createTestUsageStats(t, db, 150000000000000, 1, 25, 6) // 0.00015 ETH, 1 tx, 25 hours ago (outside window), nonce 6

		// Verify that only transactions within time window are counted
		userOpOrm := orm.NewUserOperation(db)
		stats, err := userOpOrm.GetWalletUsageStatsExcludingSameSenderAndNonce(context.Background(), "test-api-key", 1, testSenderAddress1, big.NewInt(999), 24)
		require.NoError(t, err)

		// Should count 5 transactions (2+3) and total amount of 0.0003 ETH (0.0001+0.0002)
		assert.Equal(t, int64(5), stats.TransactionCount)
		assert.Equal(t, int64(299999999999998), stats.TotalWeiAmount) // 0.0003 ETH
		assert.NotNil(t, stats.EarliestTransactionTime)

		// New operation should still succeed as we're within limits
		userOp := createTestUserOp(testSenderAddress1, 20) // Use different nonce
		w := makePaymasterRequest(t, router, "pm_getPaymasterStubData", userOp, 1, testETHAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Nil(t, resp.Error)
	})
}

func TestPaymasterController_TokenPayments(t *testing.T) {
	t.Run("USDTPayment_NoQuotaCheck_GetPaymasterStubData", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "0.000000000000000001", 24, 10) // Very low ETH limit

		// Create existing ETH usage that would exceed the limit
		createTestUsageStats(t, db, 1000000000000000, 1, 1, 0) // 0.001 ETH

		userOp := createTestUserOp(testSenderAddress1, 10)

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
				"token":     "0xf55bec9cafdbe8730f096aa55dad6d22d44099df", // USDT address
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

		// Should succeed even with existing ETH usage because USDT payments don't check ETH quota
		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)
	})

	t.Run("USDTPayment_NoQuotaCheck_GetPaymasterData", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "0.000000000000000001", 24, 10) // Very low ETH limit

		// Create existing ETH usage that would exceed the limit
		createTestUsageStats(t, db, 1000000000000000, 1, 1, 0) // 0.001 ETH

		paymasterVerificationGasLimit, paymasterPostOpGasLimit := calculatePaymasterGasLimits(testUSDTAddress, testUSDTAddress, testUSDCAddress)
		userOp := createTestUserOpWithPaymasterGasLimits(
			testSenderAddress1,
			10,
			paymasterVerificationGasLimit,
			paymasterPostOpGasLimit,
		)

		// Make request with USDC token
		reqBody := types.PaymasterJSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "pm_getPaymasterData",
			ID:      1,
		}

		params := []interface{}{
			userOp,
			"0x0000000071727De22E5E9d8BAf0edAc6f37da032", // EntryPoint v0.7
			"0x82750", // Chain ID (Scroll mainnet)
			map[string]interface{}{
				"policy_id": 1,
				"token":     "0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4", // USDC address
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

		// Should succeed even with existing ETH usage because USDC payments don't check ETH quota
		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)
	})
}

func TestPaymasterController_PaymasterDataValidation_BadCases(t *testing.T) {
	t.Run("GetPaymasterData_WithIncorrectGasLimits_ETH", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24, 10)

		wrongVerificationGas := big.NewInt(99999)
		wrongPostOpGas := big.NewInt(99999)

		userOp := createTestUserOpWithPaymasterGasLimits(
			testSenderAddress1,
			1,
			wrongVerificationGas,
			wrongPostOpGas,
		)

		w := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1, testETHAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Gas limit mismatch")
	})

	t.Run("GetPaymasterData_MissingGasLimits_ETH", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24, 10)

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1, testETHAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "is required for pm_getPaymasterData")
	})

	t.Run("GetPaymasterData_WithIncorrectGasLimits_USDT", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24, 10)

		wrongVerificationGas := big.NewInt(99999)
		wrongPostOpGas := big.NewInt(99999)

		userOp := createTestUserOpWithPaymasterGasLimits(
			testSenderAddress2,
			2,
			wrongVerificationGas,
			wrongPostOpGas,
		)

		w := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1, testUSDTAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "Gas limit mismatch")
	})

	t.Run("GetPaymasterData_MissingGasLimits_USDT", func(t *testing.T) {
		db := setupTestDB(t)
		router := setupPaymasterTestRouter(db)
		createTestPolicy(t, db, "1.0", 24, 10)

		userOp := createTestUserOp(testSenderAddress1, 1)
		w := makePaymasterRequest(t, router, "pm_getPaymasterData", userOp, 1, testUSDTAddress)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp types.PaymasterJSONRPCResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, types.InvalidParamsCode, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "is required for pm_getPaymasterData")
	})
}
