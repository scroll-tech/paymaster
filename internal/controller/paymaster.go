package controller

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/log"
	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/types"
)

// Constants for RPC Errors (as per JSON-RPC 2.0 spec and EIP-1474)
const (
	entryPointV7Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
)

// Zero address constant
var emptyAddr = common.Address{}

// PaymasterController the controller of paymaster
type PaymasterController struct {
	cfg       *config.Config
	signerKey *ecdsa.PrivateKey
}

// NewPaymasterController creates and initializes a new PaymasterController.
func NewPaymasterController(cfg *config.Config) *PaymasterController {
	if cfg.APIKey == "" {
		log.Crit("API key is required")
	}

	privateKeyBytes, err := hex.DecodeString(cfg.SignerPrivateKey)
	if err != nil {
		log.Crit("Failed to decode private key", "error", err)
	}

	signerKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Crit("Failed to create ECDSA key from private key", "error", err)
	}

	log.Info("Paymaster signer initialized", "address", crypto.PubkeyToAddress(signerKey.PublicKey).Hex())

	return &PaymasterController{
		cfg:       cfg,
		signerKey: signerKey,
	}
}

// Paymaster the handler of paymaster
func (pc *PaymasterController) Paymaster(c *gin.Context) {
	var req types.PaymasterJSONRPCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		types.SendError(c, nil, types.ParseErrorCode, "Parse error")
		return
	}

	if req.JSONRPC != types.JSONRPCVersion {
		types.SendError(c, req.ID, types.InvalidRequestCode, "Invalid JSON-RPC version")
		return
	}

	switch req.Method {
	case "pm_getPaymasterStubData":
		pc.handleGetPaymasterStubData(c, req)
	case "pm_getPaymasterData":
		pc.handleGetPaymasterData(c, req)
	default:
		log.Debug("Method not found", "method", req.Method)
		types.SendError(c, req.ID, types.MethodNotFoundCode, "Method not found: "+req.Method)
	}
}

// handleGetPaymasterStubData implements the logic for pm_getPaymasterStubData.
func (pc *PaymasterController) handleGetPaymasterStubData(c *gin.Context, req types.PaymasterJSONRPCRequest) {
	params, tokenAddr, rpcErr := pc.parseERC7677Params(req.Params)
	if rpcErr != nil {
		types.SendError(c, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	// Generate signed paymaster data for stub
	paymasterData, verificationGasLimit, paymasterPostOpGasLimit, err := pc.buildAndSignPaymasterData(params, tokenAddr)
	if err != nil {
		log.Error("Failed to build and sign paymaster data for stub", "error", err)
		types.SendError(c, req.ID, types.PaymasterDataGenErrorCode, "Failed to generate paymaster data")
		return
	}

	stubResult := types.GetPaymasterStubDataResultV7{
		Paymaster:                     pc.cfg.PaymasterAddressV7,
		PaymasterData:                 paymasterData,
		PaymasterPostOpGasLimit:       hexutil.EncodeBig(paymasterPostOpGasLimit),
		PaymasterVerificationGasLimit: hexutil.EncodeBig(verificationGasLimit),
	}

	log.Debug("Return stub data", "result", stubResult)
	types.SendSuccess(c, req.ID, stubResult)
}

// handleGetPaymasterData implements the logic for pm_getPaymasterData.
func (pc *PaymasterController) handleGetPaymasterData(c *gin.Context, req types.PaymasterJSONRPCRequest) {
	params, tokenAddr, rpcErr := pc.parseERC7677Params(req.Params)
	if rpcErr != nil {
		types.SendError(c, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	// Generate signed paymaster data
	paymasterData, _, _, err := pc.buildAndSignPaymasterData(params, tokenAddr)
	if err != nil {
		log.Error("Failed to build and sign paymaster data", "error", err)
		types.SendError(c, req.ID, types.PaymasterDataGenErrorCode, "Failed to generate paymaster data")
		return
	}

	result := types.GetPaymasterDataResultV7{
		Paymaster:     pc.cfg.PaymasterAddressV7,
		PaymasterData: paymasterData,
	}

	log.Debug("Return final paymaster data", "result", result)
	types.SendSuccess(c, req.ID, result)
}

func (pc *PaymasterController) parseERC7677Params(rawParams json.RawMessage) (*types.PaymasterUserOperationV7, common.Address, *types.RPCError) {
	var p []json.RawMessage
	if err := json.Unmarshal(rawParams, &p); err != nil || len(p) != 4 { // Need exactly 4 elements for ERC-7677
		log.Debug("Invalid params structure", "params", string(rawParams), "error", err, "length", len(p))
		return nil, common.Address{}, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid params structure: expected an array of exactly 4 elements including context"}
	}

	var userOp *types.PaymasterUserOperationV7
	if err := json.Unmarshal(p[0], &userOp); err != nil {
		log.Debug("Invalid userOp param", "userOp", string(p[0]), "error", err)
		return nil, common.Address{}, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid userOp param"}
	}

	var entryPoint string
	if err := json.Unmarshal(p[1], &entryPoint); err != nil {
		log.Debug("Invalid entryPoint param", "entryPoint", entryPoint, "error", err)
		return nil, common.Address{}, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid entryPoint param"}
	}

	if !strings.EqualFold(entryPoint, entryPointV7Address) {
		log.Debug("Unsupported EntryPoint version", "entryPoint", entryPoint, "expected", entryPointV7Address)
		return nil, common.Address{}, &types.RPCError{Code: types.UnsupportedEntryPointCode, Message: "Unsupported EntryPoint version. Only v0.7 is supported (" + entryPointV7Address + ")."}
	}

	var chainIDStr string
	if err := json.Unmarshal(p[2], &chainIDStr); err != nil {
		log.Debug("Invalid chainId param", "chainId", string(p[2]), "error", err)
		return nil, common.Address{}, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid chainId param"}
	}

	inputChainID, success := new(big.Int).SetString(strings.TrimPrefix(chainIDStr, "0x"), 16)
	if !success {
		log.Debug("Failed to parse chainId", "chainId", chainIDStr)
		return nil, common.Address{}, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid chainId format"}
	}

	if inputChainID.Cmp(big.NewInt(pc.cfg.ChainID)) != 0 {
		log.Debug("Unsupported chainId", "chainId", inputChainID.String(), "expected", pc.cfg.ChainID)
		return nil, common.Address{}, &types.RPCError{Code: types.UnsupportedChainIDCode, Message: "Unsupported chainId. Only " + fmt.Sprint(pc.cfg.ChainID) + " is supported."}
	}

	type ERC7677Context struct {
		Token string `json:"token"`
	}

	var context *ERC7677Context
	if err := json.Unmarshal(p[3], &context); err != nil {
		log.Debug("Invalid context param", "context", string(p[3]), "error", err)
		return nil, common.Address{}, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid context param"}
	}

	// Return the result of ETH payment
	if context == nil || context.Token == "" {
		return userOp, common.Address{}, nil
	}

	tokenAddr := common.HexToAddress(context.Token)
	if tokenAddr != emptyAddr && !strings.EqualFold(tokenAddr.Hex(), pc.cfg.USDTAddress.Hex()) {
		log.Debug("Unsupported token", "provided", tokenAddr.Hex(), "expected", pc.cfg.USDTAddress.Hex())
		return nil, common.Address{}, &types.RPCError{Code: types.UnsupportedTokenErrorCode, Message: "Unsupported token. Only " + pc.cfg.USDTAddress.Hex() + " is supported."}
	}

	// Return the token address
	return userOp, tokenAddr, nil
}

// getETHUSDTExchangeRate fetches ETH/USDT prices from Chainlink with a 5% premium.
func (pc *PaymasterController) getETHUSDTExchangeRate() (*big.Int, error) {
	chainlinkPrice, err := pc.getChainlinkPrice()
	if err != nil {
		return nil, fmt.Errorf("failed to get Chainlink price: %w", err)
	}

	log.Debug("Using Chainlink price", "price", chainlinkPrice.String())

	// Apply 5% premium and convert to 6 decimals (USDT format)
	priceWithPremium := new(big.Float).Mul(chainlinkPrice, big.NewFloat(1.05))
	priceWithDecimals := new(big.Float).Mul(priceWithPremium, big.NewFloat(1000000))
	result, _ := priceWithDecimals.Int(nil)

	log.Debug("Calculated Chainlink ETH/USDT price with premium", "original", chainlinkPrice.String(), "with_premium", result.String())
	return result, nil
}

// getChainlinkPrice fetches USDT/ETH price from Chainlink and converts to ETH/USDT
func (pc *PaymasterController) getChainlinkPrice() (*big.Float, error) {
	aggregatorAddress := "0xEe9F2375b4bdF6387aa8265dD4FB8F16512A1d46"
	functionSelector := "0x50d25bcd"

	// Try each RPC URL
	for i, rpcURL := range pc.cfg.EthereumRPCURLs {
		log.Debug("Trying RPC endpoint", "index", i, "url", rpcURL)

		client := &http.Client{Timeout: 2 * time.Second}
		payload := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "eth_call",
			"params": []interface{}{
				map[string]string{
					"to":   aggregatorAddress,
					"data": functionSelector,
				},
				"latest",
			},
			"id": 1,
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Error("Failed to marshal request", "rpc", rpcURL, "error", err)
			continue
		}

		resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Error("Failed to call RPC", "rpc", rpcURL, "error", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", "rpc", rpcURL, "error", closeErr)
		}
		if err != nil {
			log.Error("Failed to read response", "rpc", rpcURL, "error", err)
			continue
		}

		var rpcResponse struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}

		if err = json.Unmarshal(body, &rpcResponse); err != nil {
			log.Error("Failed to parse response", "rpc", rpcURL, "error", err)
			continue
		}

		if rpcResponse.Error != nil {
			log.Error("RPC error", "rpc", rpcURL, "error", rpcResponse.Error.Message)
			continue
		}

		if len(rpcResponse.Result) < 66 {
			log.Error("Invalid response", "rpc", rpcURL, "result", rpcResponse.Result)
			continue
		}

		// Parse answer
		answerHex := rpcResponse.Result[2:]
		answer, ok := new(big.Int).SetString(answerHex, 16)
		if !ok || answer.Sign() <= 0 {
			log.Error("Invalid answer", "rpc", rpcURL, "hex", answerHex)
			continue
		}

		// Convert USDT/ETH to ETH/USDT
		usdtPerEth := new(big.Float).SetInt(answer)
		divisor := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		usdtPerEth.Quo(usdtPerEth, divisor)

		if usdtPerEth.Sign() <= 0 {
			log.Error("Invalid price", "rpc", rpcURL, "price", usdtPerEth.String())
			continue
		}

		ethPerUsdt := new(big.Float).Quo(big.NewFloat(1.0), usdtPerEth)
		log.Debug("Got Chainlink price", "rpc", rpcURL, "eth_usdt", ethPerUsdt.String())
		return ethPerUsdt, nil
	}

	return nil, fmt.Errorf("all RPC endpoints failed")
}

// buildAndSignPaymasterData builds and signs paymaster data
func (pc *PaymasterController) buildAndSignPaymasterData(userOp *types.PaymasterUserOperationV7, tokenAddr common.Address) (string, *big.Int, *big.Int, error) {
	// Current timestamp in seconds
	currentTime := time.Now().Unix()

	// Set validity window
	validUntil := big.NewInt(currentTime + 3600) // current time + 1 hour
	validAfter := big.NewInt(currentTime - 3600) // current time - 1 hour

	// Sponsor UUID, default to zero
	sponsorUUID := big.NewInt(0)

	// Configuration flags
	allowAnyBundler := true
	precheckBalance := true
	prepaymentRequired := false

	// Set default values for ETH
	exchangeRate := big.NewInt(0) // Zero for ETH
	postOpGas := big.NewInt(5000)
	verificationGas := big.NewInt(25000)

	// If using USDT token
	if tokenAddr != emptyAddr && strings.EqualFold(tokenAddr.Hex(), pc.cfg.USDTAddress.Hex()) {
		var err error
		exchangeRate, err = pc.getETHUSDTExchangeRate() // Get exchange rate with 5% premium
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to get ETH/USDT exchange rate: %w", err)
		}
		postOpGas = big.NewInt(40000)
		verificationGas = big.NewInt(30000)
	}

	// Pack paymaster data
	paymasterData := pc.packPaymasterData(
		validUntil,
		validAfter,
		sponsorUUID,
		allowAnyBundler,
		precheckBalance,
		prepaymentRequired,
		tokenAddr,
		pc.cfg.PaymasterAddressV7, // receiver
		exchangeRate,
		postOpGas,
	)

	// Hash user operation with paymaster data
	hash := pc.getPaymasterDataHash(userOp, validUntil, validAfter, sponsorUUID, allowAnyBundler, precheckBalance, prepaymentRequired, tokenAddr, pc.cfg.PaymasterAddressV7, exchangeRate, postOpGas)

	// Sign the hash
	signature, err := pc.signHash(hash)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to sign paymaster data hash, userOp: %v, paymasterData: %x, hash: %x, error: %w", userOp, paymasterData, hex.EncodeToString(hash), err)
	}

	// Append signature to paymaster data
	paymasterDataWithSig := append(paymasterData, signature...)

	return "0x" + hex.EncodeToString(paymasterDataWithSig), verificationGas, postOpGas, nil
}

// packPaymasterData encodes the paymaster data fields according to the contract format
func (pc *PaymasterController) packPaymasterData(
	validUntil *big.Int,
	validAfter *big.Int,
	sponsorUUID *big.Int,
	allowAnyBundler bool,
	precheckBalance bool,
	prepaymentRequired bool,
	token common.Address,
	receiver common.Address,
	exchangeRate *big.Int,
	postOpGas *big.Int,
) []byte {
	var buffer []byte

	// validUntil (6 bytes - uint48)
	validUntilBytes := make([]byte, 6)
	validUntil.FillBytes(validUntilBytes)
	buffer = append(buffer, validUntilBytes...)

	// validAfter (6 bytes - uint48)
	validAfterBytes := make([]byte, 6)
	validAfter.FillBytes(validAfterBytes)
	buffer = append(buffer, validAfterBytes...)

	// sponsorUUID (16 bytes - uint128)
	sponsorUUIDBytes := make([]byte, 16)
	sponsorUUID.FillBytes(sponsorUUIDBytes)
	buffer = append(buffer, sponsorUUIDBytes...)

	// allowAnyBundler (1 byte - bool)
	if allowAnyBundler {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 0)
	}

	// precheckBalance (1 byte - bool)
	if precheckBalance {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 0)
	}

	// prepaymentRequired (1 byte - bool)
	if prepaymentRequired {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 0)
	}

	// token (20 bytes - address)
	buffer = append(buffer, token.Bytes()...)

	// receiver (20 bytes - address)
	buffer = append(buffer, receiver.Bytes()...)

	// exchangeRate (32 bytes - uint256)
	exchangeRateBytes := make([]byte, 32)
	exchangeRate.FillBytes(exchangeRateBytes)
	buffer = append(buffer, exchangeRateBytes...)

	// postOpGas (6 bytes - uint48)
	postOpGasBytes := make([]byte, 6)
	postOpGas.FillBytes(postOpGasBytes)
	buffer = append(buffer, postOpGasBytes...)

	return buffer
}

func (pc *PaymasterController) getPaymasterDataHash(userOp *types.PaymasterUserOperationV7,
	validUntil, validAfter *big.Int,
	sponsorUUID *big.Int,
	allowAnyBundler, precheckBalance, prepaymentRequired bool,
	token, receiver common.Address,
	exchangeRate, postOpGas *big.Int,
) []byte {
	var buffer []byte

	// UserOp fields (8 * 32 bytes)
	buffer = append(buffer, common.LeftPadBytes(userOp.Sender.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(userOp.Nonce.ToInt().Bytes(), 32)...)
	buffer = append(buffer, crypto.Keccak256Hash(common.FromHex(userOp.InitCode)).Bytes()...)
	buffer = append(buffer, crypto.Keccak256Hash(common.FromHex(userOp.CallData)).Bytes()...)

	gasLimits := packGasLimits(userOp.VerificationGasLimit.ToInt(), userOp.CallGasLimit.ToInt())
	buffer = append(buffer, gasLimits[:]...)

	buffer = append(buffer, common.LeftPadBytes(userOp.PreVerificationGas.ToInt().Bytes(), 32)...)

	gasFees := packGasLimits(userOp.MaxFeePerGas.ToInt(), userOp.MaxPriorityFeePerGas.ToInt())
	buffer = append(buffer, gasFees[:]...)

	buffer = append(buffer, common.LeftPadBytes(big.NewInt(pc.cfg.ChainID).Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(pc.cfg.PaymasterAddressV7.Bytes(), 32)...)

	// PaymasterData fields (10 * 32 bytes)
	buffer = append(buffer, common.LeftPadBytes(validUntil.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(validAfter.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(sponsorUUID.Bytes(), 32)...)

	if allowAnyBundler {
		buffer = append(buffer, common.LeftPadBytes([]byte{1}, 32)...)
	} else {
		buffer = append(buffer, common.LeftPadBytes([]byte{0}, 32)...)
	}

	if precheckBalance {
		buffer = append(buffer, common.LeftPadBytes([]byte{1}, 32)...)
	} else {
		buffer = append(buffer, common.LeftPadBytes([]byte{0}, 32)...)
	}

	if prepaymentRequired {
		buffer = append(buffer, common.LeftPadBytes([]byte{1}, 32)...)
	} else {
		buffer = append(buffer, common.LeftPadBytes([]byte{0}, 32)...)
	}

	buffer = append(buffer, common.LeftPadBytes(token.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(receiver.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(exchangeRate.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(postOpGas.Bytes(), 32)...)

	log.Debug("Packed data for hashing", "packedData", hexutil.Encode(buffer))

	return crypto.Keccak256(buffer)
}

func (pc *PaymasterController) signHash(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}

	prefix := "\x19Ethereum Signed Message:\n32"
	fullMessage := append([]byte(prefix), hash...)
	ethSignedHash := crypto.Keccak256(fullMessage)

	signature, err := crypto.Sign(ethSignedHash, pc.signerKey)
	if err != nil {
		return nil, err
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: got %d, expected 65", len(signature))
	}

	if signature[64] == 0 || signature[64] == 1 {
		signature[64] += 27
	}

	return signature, nil
}

func packGasLimits(high, low *big.Int) [32]byte {
	combined := new(big.Int).Or(new(big.Int).Lsh(high, 128), low)
	return [32]byte(common.LeftPadBytes(combined.Bytes(), 32))
}
