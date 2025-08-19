// Package controller provides the ERC-7677 paymaster controller for handling JSON-RPC requests.
package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/orm"
	"github.com/scroll-tech/paymaster/internal/types"
)

const entryPointV7Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

var (
	emptyAddr      = common.Address{}
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

// PaymasterController the controller of paymaster
type PaymasterController struct {
	cfg           *config.Config
	signerKey     *ecdsa.PrivateKey
	signerAddress common.Address

	awsKMSKeyID    string
	kmsClient      *kms.Client
	kmsPubKeyBytes []byte

	policyOrm        *orm.Policy
	userOperationOrm *orm.UserOperation
}

// NewPaymasterController creates and initializes a new PaymasterController.
func NewPaymasterController(cfg *config.Config, db *gorm.DB) *PaymasterController {
	if len(cfg.APIKeys) == 0 {
		log.Crit("API keys are required")
	}

	pc := &PaymasterController{
		cfg:              cfg,
		policyOrm:        orm.NewPolicy(db),
		userOperationOrm: orm.NewUserOperation(db),
	}

	// Check mutually exclusive signer configuration
	hasPrivateKey := cfg.SignerPrivateKey != ""
	hasKMSKey := cfg.AWSKMSKeyID != ""

	if !hasPrivateKey && !hasKMSKey {
		log.Crit("Either signer private key or AWS KMS key ID must be provided")
	}

	if hasPrivateKey && hasKMSKey {
		log.Crit("Cannot specify both signer private key and AWS KMS key ID")
	}

	if hasPrivateKey {
		// Initialize with private key
		if err := pc.initializePrivateKeySigner(cfg.SignerPrivateKey); err != nil {
			log.Crit("Failed to initialize private key signer", "error", err)
		}
		log.Info("Paymaster signer initialized with private key", "address", pc.signerAddress.Hex())
	} else {
		// Initialize with AWS KMS
		// FIXME: AWS KMS signer is not tested yet.
		if err := pc.initializeKMSSigner(cfg.AWSKMSKeyID); err != nil {
			log.Crit("Failed to initialize KMS signer", "error", err)
		}
		log.Info("Paymaster signer initialized with AWS KMS", "address", pc.signerAddress.Hex(), "key_id", cfg.AWSKMSKeyID)
	}

	return pc
}

// initializePrivateKeySigner initializes the signer with a private key
func (pc *PaymasterController) initializePrivateKeySigner(privateKeyHex string) error {
	// Validate input
	if privateKeyHex == "" {
		return fmt.Errorf("private key cannot be empty")
	}

	// Handle private key with or without 0x prefix
	if strings.HasPrefix(privateKeyHex, "0x") || strings.HasPrefix(privateKeyHex, "0X") {
		privateKeyHex = privateKeyHex[2:]
	}

	// Validate hex string length (64 characters for 32 bytes)
	if len(privateKeyHex) != 64 {
		return fmt.Errorf("invalid private key length: expected 64 hex characters, got %d", len(privateKeyHex))
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	signerKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to create ECDSA key from private key: %w", err)
	}

	pc.signerKey = signerKey
	pc.signerAddress = crypto.PubkeyToAddress(signerKey.PublicKey)

	// Clear sensitive data from memory
	for i := range privateKeyBytes {
		privateKeyBytes[i] = 0
	}

	return nil
}

// initializeKMSSigner initializes the signer with AWS KMS
// FIXME: AWS KMS signer is not tested yet.
func (pc *PaymasterController) initializeKMSSigner(keyID string) error {
	// Load AWS configuration
	cfg, err := awsConfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Set HTTP client timeouts
	cfg.HTTPClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   2 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
		},
	}

	// Create KMS client
	pc.kmsClient = kms.NewFromConfig(cfg)
	pc.awsKMSKeyID = keyID

	// Get public key to derive address
	pubkey, err := pc.getPubKeyFromKMS(context.Background(), keyID)
	if err != nil {
		return fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	pc.kmsPubKeyBytes = secp256k1.S256().Marshal(pubkey.X, pubkey.Y)
	pc.signerAddress = crypto.PubkeyToAddress(*pubkey)
	return nil
}

// getPubKeyFromKMS gets public key from KMS
func (pc *PaymasterController) getPubKeyFromKMS(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	getPubKeyOutput, err := pc.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot get public key from KMS for KeyId=%s: %w", keyID, err)
	}

	// Parse ASN.1 DER encoded public key
	var asn1pubk struct {
		EcPublicKeyInfo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}

	_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk)
	if err != nil {
		return nil, fmt.Errorf("cannot parse ASN.1 public key for KeyId=%s: %w", keyID, err)
	}

	pubkey, err := crypto.UnmarshalPubkey(asn1pubk.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot construct secp256k1 public key from key bytes: %w", err)
	}

	return pubkey, nil
}

// signHashWithKMS signs a hash using AWS KMS
func (pc *PaymasterController) signHashWithKMS(hash []byte) ([]byte, error) {
	// Get the expected public key bytes for signature verification
	if pc.kmsPubKeyBytes == nil {
		return nil, fmt.Errorf("KMS public key not initialized")
	}

	// Get R and S values from KMS signature
	rBytes, sBytes, err := pc.getSignatureFromKMS(context.Background(), hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature from KMS: %w", err)
	}

	// Adjust S value according to Ethereum standard
	sBigInt := new(big.Int).SetBytes(sBytes)
	if sBigInt.Cmp(secp256k1HalfN) > 0 {
		sBytes = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
	}

	// Get Ethereum signature with correct recovery ID
	signature, err := pc.getEthereumSignature(pc.kmsPubKeyBytes, hash, rBytes, sBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to get Ethereum signature: %w", err)
	}

	return signature, nil
}

// getSignatureFromKMS gets R and S values from KMS
func (pc *PaymasterController) getSignatureFromKMS(ctx context.Context, hash []byte) ([]byte, []byte, error) {
	signInput := &kms.SignInput{
		KeyId:            aws.String(pc.awsKMSKeyID),
		SigningAlgorithm: awsTypes.SigningAlgorithmSpecEcdsaSha256,
		MessageType:      awsTypes.MessageTypeDigest,
		Message:          hash,
	}

	signOutput, err := pc.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return nil, nil, fmt.Errorf("KMS sign failed: %w", err)
	}

	// Parse ASN.1 signature
	var sigAsn1 struct {
		R asn1.RawValue
		S asn1.RawValue
	}

	_, err = asn1.Unmarshal(signOutput.Signature, &sigAsn1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal ASN.1 signature: %w", err)
	}

	return sigAsn1.R.Bytes, sigAsn1.S.Bytes, nil
}

// getEthereumSignature creates Ethereum signature with recovery ID
func (pc *PaymasterController) getEthereumSignature(expectedPublicKeyBytes []byte, hash []byte, r []byte, s []byte) ([]byte, error) {
	rsSignature := append(pc.adjustSignatureLength(r), pc.adjustSignatureLength(s)...)

	// Try recovery ID 0
	signature := append(rsSignature, []byte{0}...)
	recoveredPublicKeyBytes, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return nil, fmt.Errorf("recovery with ID 0 failed: %w", err)
	}

	if hex.EncodeToString(recoveredPublicKeyBytes) == hex.EncodeToString(expectedPublicKeyBytes) {
		return signature, nil
	}

	// Try recovery ID 1
	signature = append(rsSignature, []byte{1}...)
	recoveredPublicKeyBytes, err = crypto.Ecrecover(hash, signature)
	if err != nil {
		return nil, fmt.Errorf("recovery with ID 1 failed: %w", err)
	}

	if hex.EncodeToString(recoveredPublicKeyBytes) == hex.EncodeToString(expectedPublicKeyBytes) {
		return signature, nil
	}

	return nil, fmt.Errorf("cannot reconstruct public key from signature")
}

// adjustSignatureLength adjusts signature component length
func (pc *PaymasterController) adjustSignatureLength(buffer []byte) []byte {
	buffer = bytes.TrimLeft(buffer, "\x00")
	for len(buffer) < 32 {
		zeroBuf := []byte{0}
		buffer = append(zeroBuf, buffer...)
	}
	return buffer
}

// signHashWithPrivateKey signs a hash using the private key
func (pc *PaymasterController) signHashWithPrivateKey(hash []byte) ([]byte, error) {
	signature, err := crypto.Sign(hash, pc.signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with private key: %w", err)
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: got %d, expected 65", len(signature))
	}

	if signature[64] == 0 || signature[64] == 1 {
		signature[64] += 27
	}

	return signature, nil
}

// handlePaymasterMethod handles JSON-RPC requests for paymaster methods.
func (pc *PaymasterController) handlePaymasterMethod(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	switch req.Method {
	case "pm_getPaymasterStubData":
		pc.handleGetPaymasterStubData(c, req, apiKey)
	case "pm_getPaymasterData":
		pc.handleGetPaymasterData(c, req, apiKey)
	default:
		log.Debug("Method not found", "method", req.Method)
		types.SendError(c, req.ID, types.MethodNotFoundCode, "Method not found: "+req.Method)
	}
}

// handleGetPaymasterStubData implements the logic for pm_getPaymasterStubData.
func (pc *PaymasterController) handleGetPaymasterStubData(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	params, tokenAddr, policyID, rpcErr := pc.parseERC7677Params(req.Params)
	if rpcErr != nil {
		types.SendError(c, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	paymasterVerificationGasLimit, paymasterPostOpGasLimit := calculatePaymasterGasLimits(tokenAddr, pc.cfg.USDTAddress, pc.cfg.USDCAddress)

	// Check quota and create record only for ETH payments
	if tokenAddr == emptyAddr {
		estimatedWei := pc.calculateEstimatedWei(params, paymasterVerificationGasLimit, paymasterPostOpGasLimit)

		// Check quota first
		if err := pc.checkQuota(c.Request.Context(), apiKey, policyID, params.Sender, estimatedWei); err != nil {
			log.Error("Quota check failed", "error", err, "sender", params.Sender.Hex(), "nonce", params.Nonce.String(), "policy_id", policyID)
			types.SendError(c, req.ID, types.QuotaExceededErrorCode, "Quota exceeded")
			return
		}

		// Create or update record
		if err := pc.createOrUpdateRecord(c.Request.Context(), apiKey, policyID, params.Sender, params.Nonce.ToInt(), estimatedWei, orm.UserOperationStatusPaymasterStubDataProvided); err != nil {
			log.Error("Failed to create or update operation record", "error", err, "sender", params.Sender.Hex(), "nonce", params.Nonce.String(), "policy_id", policyID)
			types.SendError(c, req.ID, types.InternalErrorCode, "Operation failed")
			return
		}
	} else {
		log.Debug("Token payment detected, skipping quota check and record creation", "token", tokenAddr.Hex(), "sender", params.Sender.Hex(), "nonce", params.Nonce.String())
	}

	// Generate signed paymaster data for stub
	paymasterData, err := pc.buildAndSignPaymasterData(params, tokenAddr, paymasterVerificationGasLimit, paymasterPostOpGasLimit)
	if err != nil {
		log.Error("Failed to build and sign paymaster data for stub", "error", err)
		types.SendError(c, req.ID, types.PaymasterDataGenErrorCode, "Failed to generate paymaster data")
		return
	}

	stubResult := types.GetPaymasterStubDataResultV7{
		Paymaster:                     pc.cfg.PaymasterAddressV7,
		PaymasterData:                 paymasterData,
		PaymasterPostOpGasLimit:       hexutil.EncodeBig(paymasterPostOpGasLimit),
		PaymasterVerificationGasLimit: hexutil.EncodeBig(paymasterVerificationGasLimit),
	}

	log.Debug("Return stub data", "result", stubResult)
	types.SendSuccess(c, req.ID, stubResult)
}

// handleGetPaymasterData implements the logic for pm_getPaymasterData.
func (pc *PaymasterController) handleGetPaymasterData(c *gin.Context, req types.PaymasterJSONRPCRequest, apiKey string) {
	params, tokenAddr, policyID, rpcErr := pc.parseERC7677Params(req.Params)
	if rpcErr != nil {
		types.SendError(c, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	paymasterVerificationGasLimit, paymasterPostOpGasLimit := calculatePaymasterGasLimits(tokenAddr, pc.cfg.USDTAddress, pc.cfg.USDCAddress)

	// Validate paymaster related gas limits
	if err := validateClientGasLimits(params, paymasterVerificationGasLimit, paymasterPostOpGasLimit); err != nil {
		log.Error("Gas limit validation failed", "error", err, "sender", params.Sender.Hex())
		types.SendError(c, req.ID, types.InvalidParamsCode, fmt.Sprintf("Gas limit mismatch: %v", err))
		return
	}

	// Check quota and update operation record only for ETH payments
	if tokenAddr == emptyAddr {
		finalWei := pc.calculateEstimatedWei(params, paymasterVerificationGasLimit, paymasterPostOpGasLimit)

		// Check quota first
		if err := pc.checkQuota(c.Request.Context(), apiKey, policyID, params.Sender, finalWei); err != nil {
			log.Error("Quota check failed", "error", err, "sender", params.Sender.Hex(), "nonce", params.Nonce.String(), "policy_id", policyID)
			types.SendError(c, req.ID, types.QuotaExceededErrorCode, "Quota exceeded")
			return
		}

		// Create or update record
		if err := pc.createOrUpdateRecord(c.Request.Context(), apiKey, policyID, params.Sender, params.Nonce.ToInt(), finalWei, orm.UserOperationStatusPaymasterDataProvided); err != nil {
			log.Error("Failed to create or update operation record", "error", err, "sender", params.Sender.Hex(), "nonce", params.Nonce.String(), "policy_id", policyID)
			types.SendError(c, req.ID, types.InternalErrorCode, "Operation failed")
			return
		}
	} else {
		log.Debug("Token payment detected, skipping quota check and record creation", "token", tokenAddr.Hex(), "sender", params.Sender.Hex(), "nonce", params.Nonce.String())
	}

	// Generate signed paymaster data
	paymasterData, err := pc.buildAndSignPaymasterData(params, tokenAddr, paymasterVerificationGasLimit, paymasterPostOpGasLimit)
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

// checkQuota verifies if the operation would exceed quota limits
func (pc *PaymasterController) checkQuota(ctx context.Context, apiKey string, policyID int64, sender common.Address, weiAmount *big.Int) error {
	// Get policy to check limits
	policy, err := pc.policyOrm.GetByAPIKeyAndPolicyID(ctx, apiKey, policyID)
	if err != nil {
		return fmt.Errorf("failed to get policy, policy_id: %d, error: %w", policyID, err)
	}

	// Get current usage
	currentUsageWei, err := pc.userOperationOrm.GetWalletUsage(ctx, apiKey, policyID, sender.Hex(), policy.Limits.TimeWindowHours)
	if err != nil {
		return fmt.Errorf("failed to get current usage: %w", err)
	}

	// Parse max limit from ETH to wei
	maxEthFloat, ok := new(big.Float).SetPrec(256).SetString(policy.Limits.MaxEthPerWalletPerWindow)
	if !ok {
		return fmt.Errorf("invalid max ETH limit: %s", policy.Limits.MaxEthPerWalletPerWindow)
	}

	// Convert ETH to wei (18 decimals)
	weiPerEth := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	maxLimitWei, accuracy := new(big.Float).Mul(maxEthFloat, new(big.Float).SetInt(weiPerEth)).Int(nil)
	if accuracy != big.Exact {
		return fmt.Errorf("invalid max ETH limit: original=%s, converted_wei=%s, accuracy=%d", policy.Limits.MaxEthPerWalletPerWindow, maxLimitWei.String(), accuracy)
	}

	// Check if new operation would exceed limit
	currentUsage := big.NewInt(currentUsageWei)
	newTotal := new(big.Int).Add(currentUsage, weiAmount)

	if newTotal.Cmp(maxLimitWei) > 0 {
		log.Debug("Quota exceeded", "sender", sender.Hex(), "current_usage_wei", currentUsage.String(), "estimated_wei", weiAmount.String(), "new_total_wei", newTotal.String(), "max_limit_wei", maxLimitWei.String(), "max_limit_eth", policy.Limits.MaxEthPerWalletPerWindow)

		// Convert back to ETH for user-friendly error message
		currentUsageEth := new(big.Float).Quo(new(big.Float).SetInt(currentUsage), new(big.Float).SetInt(weiPerEth))
		newTotalEth := new(big.Float).Quo(new(big.Float).SetInt(newTotal), new(big.Float).SetInt(weiPerEth))

		return fmt.Errorf("quota exceeded: current usage %.6f ETH + new operation would total %.6f ETH, limit is %s ETH", currentUsageEth, newTotalEth, policy.Limits.MaxEthPerWalletPerWindow)
	}

	return nil
}

// createOrUpdateRecord creates or updates the operation record
func (pc *PaymasterController) createOrUpdateRecord(ctx context.Context, apiKey string, policyID int64, sender common.Address, nonce *big.Int, weiAmount *big.Int, status orm.UserOperationStatus) error {
	userOp := &orm.UserOperation{
		APIKeyHash: crypto.Keccak256Hash([]byte(apiKey)).Hex(),
		PolicyID:   policyID,
		Sender:     sender.Hex(),
		Nonce:      nonce.Int64(),
		WeiAmount:  weiAmount.Int64(),
		Status:     status,
	}

	err := pc.userOperationOrm.CreateOrUpdate(ctx, userOp)
	if err != nil {
		return fmt.Errorf("failed to create or update user operation: %w", err)
	}

	log.Debug("Operation record updated", "sender", sender.Hex(), "nonce", nonce.String(), "wei_amount", weiAmount.String(), "policy_id", policyID, "status", status)

	return nil
}

// calculateEstimatedWei calculates the estimated wei cost for the user operation
func (pc *PaymasterController) calculateEstimatedWei(userOp *types.PaymasterUserOperationV7, paymasterVerificationGas, paymasterPostOpGas *big.Int) *big.Int {
	// Calculate total gas cost
	verificationGas := userOp.VerificationGasLimit.ToInt()
	callGas := userOp.CallGasLimit.ToInt()
	preVerificationGas := userOp.PreVerificationGas.ToInt()
	maxFeePerGas := userOp.MaxFeePerGas.ToInt()

	// Total gas = userOp gas + paymaster gas
	totalGas := new(big.Int)
	totalGas.Add(totalGas, verificationGas)
	totalGas.Add(totalGas, callGas)
	totalGas.Add(totalGas, preVerificationGas)
	totalGas.Add(totalGas, paymasterVerificationGas)
	totalGas.Add(totalGas, paymasterPostOpGas)

	// Total cost = totalGas * maxFeePerGas
	return new(big.Int).Mul(totalGas, maxFeePerGas)
}

func (pc *PaymasterController) parseERC7677Params(rawParams json.RawMessage) (*types.PaymasterUserOperationV7, common.Address, int64, *types.RPCError) {
	var p []json.RawMessage
	if err := json.Unmarshal(rawParams, &p); err != nil || len(p) != 4 { // Need exactly 4 elements for ERC-7677
		log.Debug("Invalid params structure", "params", string(rawParams), "error", err, "length", len(p))
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid params structure: expected an array of exactly 4 elements including context"}
	}

	var userOp *types.PaymasterUserOperationV7
	if err := json.Unmarshal(p[0], &userOp); err != nil {
		log.Debug("Invalid userOp param", "userOp", string(p[0]), "error", err)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid userOp param"}
	}

	var entryPoint string
	if err := json.Unmarshal(p[1], &entryPoint); err != nil {
		log.Debug("Invalid entryPoint param", "entryPoint", entryPoint, "error", err)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid entryPoint param"}
	}

	if !strings.EqualFold(entryPoint, entryPointV7Address) {
		log.Debug("Unsupported EntryPoint version", "entryPoint", entryPoint, "expected", entryPointV7Address)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.UnsupportedEntryPointCode, Message: "Unsupported EntryPoint version. Only v0.7 is supported (" + entryPointV7Address + ")."}
	}

	var chainIDStr string
	if err := json.Unmarshal(p[2], &chainIDStr); err != nil {
		log.Debug("Invalid chainId param", "chainId", string(p[2]), "error", err)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid chainId param"}
	}

	inputChainID, success := new(big.Int).SetString(strings.TrimPrefix(chainIDStr, "0x"), 16)
	if !success {
		log.Debug("Failed to parse chainId", "chainId", chainIDStr)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid chainId format"}
	}

	if inputChainID.Cmp(big.NewInt(pc.cfg.ChainID)) != 0 {
		log.Debug("Unsupported chainId", "chainId", inputChainID.String(), "expected", pc.cfg.ChainID)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.UnsupportedChainIDCode, Message: "Unsupported chainId. Only " + fmt.Sprint(pc.cfg.ChainID) + " is supported."}
	}

	type ERC7677Context struct {
		Token    string `json:"token"`
		PolicyID *int64 `json:"policy_id"`
	}

	var context *ERC7677Context
	if err := json.Unmarshal(p[3], &context); err != nil {
		log.Debug("Invalid context param", "context", string(p[3]), "error", err)
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid context param"}
	}

	// Validate required context fields
	if context == nil {
		log.Debug("Missing context")
		return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Context is required"}
	}

	// Handle token address
	tokenAddr := common.Address{}
	if context.Token != "" {
		tokenAddr = common.HexToAddress(context.Token)
		if tokenAddr != emptyAddr && !pc.isSupportedToken(tokenAddr) {
			log.Debug("Unsupported token", "provided", tokenAddr.Hex(), "supported", pc.getSupportedTokensString())
			return nil, common.Address{}, 0, &types.RPCError{
				Code:    types.UnsupportedTokenErrorCode,
				Message: "Unsupported token. Supported tokens: " + pc.getSupportedTokensString(),
			}
		}
	}

	// Policy ID validation: required only for ETH payments (empty token address)
	var policyID int64 // Default value for token payments
	if tokenAddr == emptyAddr {
		// ETH payment requires policy_id
		if context.PolicyID == nil {
			log.Debug("Missing policy_id in context for ETH payment")
			return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "policy_id is required in context for ETH payments"}
		}

		if *context.PolicyID < 0 {
			log.Debug("Invalid policy_id", "policy_id", *context.PolicyID)
			return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid policy_id. It must be a non-negative integer."}
		}

		policyID = *context.PolicyID
	} else {
		// Token payment: policy_id is optional, use provided value or default to 0
		if context.PolicyID != nil {
			if *context.PolicyID < 0 {
				log.Debug("Invalid policy_id", "policy_id", *context.PolicyID)
				return nil, common.Address{}, 0, &types.RPCError{Code: types.InvalidParamsCode, Message: "Invalid policy_id. It must be a non-negative integer."}
			}
			policyID = *context.PolicyID
		}
		log.Debug("Token payment detected, policy_id not required", "token", tokenAddr.Hex(), "policy_id", policyID, "sender", userOp.Sender.Hex(), "nonce", userOp.Nonce.String())
	}

	return userOp, tokenAddr, policyID, nil
}

// getTokenExchangeRate returns the exchange rate for the specified token
func (pc *PaymasterController) getTokenExchangeRate(tokenAddr common.Address) (*big.Int, error) {
	if tokenAddr == emptyAddr {
		return big.NewInt(0), nil // ETH doesn't need exchange rate
	}

	if strings.EqualFold(tokenAddr.Hex(), pc.cfg.USDCAddress.Hex()) {
		return pc.getETHUSDCExchangeRate()
	}

	if strings.EqualFold(tokenAddr.Hex(), pc.cfg.USDTAddress.Hex()) {
		return pc.getETHUSDTExchangeRate()
	}

	return nil, fmt.Errorf("unsupported token address: %s", tokenAddr.Hex())
}

// getETHUSDTExchangeRate fetches ETH/USDT exchange rate with a 5% premium
func (pc *PaymasterController) getETHUSDTExchangeRate() (*big.Int, error) {
	// USDT/ETH price aggregator address
	aggregatorAddress := "0xEe9F2375b4bdF6387aa8265dD4FB8F16512A1d46"

	chainlinkPrice, err := pc.getChainlinkETHPrice(aggregatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get Chainlink USDT price: %w", err)
	}

	log.Debug("Using Chainlink price for USDT", "price", chainlinkPrice.String())

	// Apply 5% premium and convert to 6 decimals (USDT format)
	priceWithPremium := new(big.Float).Mul(chainlinkPrice, big.NewFloat(1.05))
	priceWithDecimals := new(big.Float).Mul(priceWithPremium, big.NewFloat(1000000))
	result, _ := priceWithDecimals.Int(nil)

	log.Debug("Calculated Chainlink ETH/USDT price with premium", "original", chainlinkPrice.String(), "with_premium", result.String())
	return result, nil
}

// getETHUSDCExchangeRate fetches ETH/USDC exchange rate with a 5% premium
func (pc *PaymasterController) getETHUSDCExchangeRate() (*big.Int, error) {
	// USDC/ETH price aggregator address
	aggregatorAddress := "0x986b5E1e1755e3C2440e960477f25201B0a8bbD4"

	chainlinkPrice, err := pc.getChainlinkETHPrice(aggregatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get Chainlink USDC price: %w", err)
	}

	log.Debug("Using Chainlink price for USDC", "price", chainlinkPrice.String())

	// Apply 5% premium and convert to 6 decimals (USDC format)
	priceWithPremium := new(big.Float).Mul(chainlinkPrice, big.NewFloat(1.05))
	priceWithDecimals := new(big.Float).Mul(priceWithPremium, big.NewFloat(1000000))
	result, _ := priceWithDecimals.Int(nil)

	log.Debug("Calculated Chainlink ETH/USDC price with premium", "original", chainlinkPrice.String(), "with_premium", result.String())
	return result, nil
}

// getChainlinkETHPrice fetches ETH/Token price from Chainlink aggregator
func (pc *PaymasterController) getChainlinkETHPrice(aggregatorAddress string) (*big.Float, error) {
	functionSelector := "0x50d25bcd" // latestRoundData()

	// Try each RPC URL
	for i, rpcURL := range pc.cfg.EthereumRPCURLs {
		log.Debug("Trying RPC endpoint for Chainlink price", "index", i, "url", rpcURL, "aggregator", aggregatorAddress)

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
			log.Error("Failed to marshal Chainlink request", "rpc", rpcURL, "aggregator", aggregatorAddress, "error", err)
			continue
		}

		resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Error("Failed to call RPC for Chainlink price", "rpc", rpcURL, "aggregator", aggregatorAddress, "error", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", "rpc", rpcURL, "error", closeErr)
		}
		if err != nil {
			log.Error("Failed to read Chainlink response", "rpc", rpcURL, "aggregator", aggregatorAddress, "error", err)
			continue
		}

		var rpcResponse struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}

		if err = json.Unmarshal(body, &rpcResponse); err != nil {
			log.Error("Failed to parse Chainlink response", "rpc", rpcURL, "aggregator", aggregatorAddress, "error", err)
			continue
		}

		if rpcResponse.Error != nil {
			log.Error("Chainlink RPC error", "rpc", rpcURL, "aggregator", aggregatorAddress, "error", rpcResponse.Error.Message)
			continue
		}

		if len(rpcResponse.Result) < 66 {
			log.Error("Invalid Chainlink response", "rpc", rpcURL, "aggregator", aggregatorAddress, "result", rpcResponse.Result)
			continue
		}

		// Parse answer (Token/ETH price with 18 decimals)
		answerHex := rpcResponse.Result[2:]
		answer, ok := new(big.Int).SetString(answerHex, 16)
		if !ok || answer.Sign() <= 0 {
			log.Error("Invalid Chainlink answer", "rpc", rpcURL, "aggregator", aggregatorAddress, "hex", answerHex)
			continue
		}

		// Convert Token/ETH to ETH/Token
		tokenPerEth := new(big.Float).SetInt(answer)
		divisor := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		tokenPerEth.Quo(tokenPerEth, divisor)

		if tokenPerEth.Sign() <= 0 {
			log.Error("Invalid token price", "rpc", rpcURL, "aggregator", aggregatorAddress, "price", tokenPerEth.String())
			continue
		}

		ethPerToken := new(big.Float).Quo(big.NewFloat(1.0), tokenPerEth)
		log.Debug("Got Chainlink price", "rpc", rpcURL, "aggregator", aggregatorAddress, "eth_per_token", ethPerToken.String())
		return ethPerToken, nil
	}

	return nil, fmt.Errorf("all RPC endpoints failed for aggregator %s", aggregatorAddress)
}

// buildAndSignPaymasterData builds and signs paymaster data
func (pc *PaymasterController) buildAndSignPaymasterData(userOp *types.PaymasterUserOperationV7, tokenAddr common.Address, paymasterVerificationGasLimit, paymasterPostOpGasLimit *big.Int) (string, error) {
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
	prepaymentRequired := true

	// Set default values for ETH
	exchangeRate := big.NewInt(0) // Zero for ETH

	// If using token
	if tokenAddr != emptyAddr {
		var err error
		exchangeRate, err = pc.getTokenExchangeRate(tokenAddr)
		if err != nil {
			return "", fmt.Errorf("failed to get exchange rate for token %s: %w", tokenAddr.Hex(), err)
		}
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
		paymasterPostOpGasLimit,
	)

	// Hash user operation with paymaster data
	hash := pc.getPaymasterDataHash(
		userOp,
		validUntil,
		validAfter,
		sponsorUUID,
		allowAnyBundler,
		precheckBalance,
		prepaymentRequired,
		tokenAddr,
		pc.cfg.PaymasterAddressV7,
		exchangeRate,
		paymasterPostOpGasLimit,
		paymasterVerificationGasLimit,
		paymasterPostOpGasLimit)

	// Sign the hash
	signature, err := pc.signHash(hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign paymaster data hash, userOp: %v, paymasterData: %s, hash: %s, error: %w", userOp, hex.EncodeToString(paymasterData), hex.EncodeToString(hash), err)
	}

	// Append signature to paymaster data
	paymasterDataWithSig := append(paymasterData, signature...)

	return "0x" + hex.EncodeToString(paymasterDataWithSig), nil
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
	paymasterValidationGasLimit, paymasterPostOpGasLimit *big.Int,
) []byte {
	var buffer []byte

	buffer = append(buffer, common.LeftPadBytes(userOp.Sender.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(userOp.Nonce.ToInt().Bytes(), 32)...)

	var initCode []byte
	if userOp.Factory != nil {
		initCode = append(userOp.Factory.Bytes(), common.FromHex(userOp.FactoryData)...)
	}
	buffer = append(buffer, crypto.Keccak256Hash(initCode).Bytes()...)

	buffer = append(buffer, crypto.Keccak256Hash(common.FromHex(userOp.CallData)).Bytes()...)

	gasLimits := packGasLimits(userOp.VerificationGasLimit.ToInt(), userOp.CallGasLimit.ToInt())
	buffer = append(buffer, gasLimits[:]...)

	buffer = append(buffer, common.LeftPadBytes(userOp.PreVerificationGas.ToInt().Bytes(), 32)...)

	gasFees := packGasLimits(userOp.MaxPriorityFeePerGas.ToInt(), userOp.MaxFeePerGas.ToInt())
	buffer = append(buffer, gasFees[:]...)

	buffer = append(buffer, common.LeftPadBytes(big.NewInt(pc.cfg.ChainID).Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(pc.cfg.PaymasterAddressV7.Bytes(), 32)...)

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

	buffer = append(buffer, common.LeftPadBytes(paymasterValidationGasLimit.Bytes(), 32)...)
	buffer = append(buffer, common.LeftPadBytes(paymasterPostOpGasLimit.Bytes(), 32)...)

	log.Debug("Packed data for hashing", "packedData", hexutil.Encode(buffer))

	return crypto.Keccak256(buffer)
}

// signHash signs a hash using either private key or AWS KMS
func (pc *PaymasterController) signHash(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}

	prefix := "\x19Ethereum Signed Message:\n32"
	fullMessage := append([]byte(prefix), hash...)
	ethSignedHash := crypto.Keccak256(fullMessage)

	if pc.signerKey != nil {
		return pc.signHashWithPrivateKey(ethSignedHash)
	}

	return pc.signHashWithKMS(ethSignedHash)
}

var max128Bit = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

func packGasLimits(high, low *big.Int) [32]byte {
	if high.Cmp(max128Bit) > 0 || low.Cmp(max128Bit) > 0 {
		panic("value exceeds 128 bits")
	}
	if high.Sign() < 0 || low.Sign() < 0 {
		panic("value cannot be negative")
	}

	combined := new(big.Int).Or(new(big.Int).Lsh(high, 128), low)
	return [32]byte(common.LeftPadBytes(combined.Bytes(), 32))
}

// calculatePaymasterGasLimits calculates the gas limits for paymaster operations based on the token address.
// The token address is either the zero address for ETH or the USDT address, validated before calling this function.
func calculatePaymasterGasLimits(tokenAddr common.Address, usdtAddress common.Address, usdcAddress common.Address) (*big.Int, *big.Int) {
	// Set default values for ETH
	paymasterPostOpGasLimit := big.NewInt(5000)
	paymasterVerificationGasLimit := big.NewInt(25000)

	// If using USDT token
	if tokenAddr != emptyAddr {
		if strings.EqualFold(tokenAddr.Hex(), usdtAddress.Hex()) || strings.EqualFold(tokenAddr.Hex(), usdcAddress.Hex()) {
			paymasterPostOpGasLimit = big.NewInt(42000)
			paymasterVerificationGasLimit = big.NewInt(35000)
		}
	}

	return paymasterVerificationGasLimit, paymasterPostOpGasLimit
}

// validateClientGasLimits validates the gas limits provided by the client against the expected values.
// This function is used in pm_getPaymasterData to ensure the client has provided correct gas limits.
func validateClientGasLimits(userOp *types.PaymasterUserOperationV7,
	expectedPaymasterVerificationGasLimit, expectedPaymasterPostOpGasLimit *big.Int,
) error {
	if userOp.PaymasterVerificationGasLimit == nil {
		return fmt.Errorf("paymasterVerificationGasLimit is required for pm_getPaymasterData")
	}

	clientPaymasterVerificationGas := userOp.PaymasterVerificationGasLimit.ToInt()
	if clientPaymasterVerificationGas.Cmp(expectedPaymasterVerificationGasLimit) != 0 {
		return fmt.Errorf("paymasterVerificationGasLimit mismatch: client=%s, expected=%s", clientPaymasterVerificationGas.String(), expectedPaymasterVerificationGasLimit.String())
	}

	if userOp.PaymasterPostOpGasLimit == nil {
		return fmt.Errorf("paymasterPostOpGasLimit is required for pm_getPaymasterData")
	}

	clientPaymasterPostOpGasLimit := userOp.PaymasterPostOpGasLimit.ToInt()
	if clientPaymasterPostOpGasLimit.Cmp(expectedPaymasterPostOpGasLimit) != 0 {
		return fmt.Errorf("paymasterPostOpGasLimit mismatch: client=%s, expected=%s", clientPaymasterPostOpGasLimit.String(), expectedPaymasterPostOpGasLimit.String())
	}

	return nil
}

// isSupportedToken checks if the token address is supported
func (pc *PaymasterController) isSupportedToken(tokenAddr common.Address) bool {
	if tokenAddr == emptyAddr {
		return true // ETH
	}
	return strings.EqualFold(tokenAddr.Hex(), pc.cfg.USDTAddress.Hex()) ||
		strings.EqualFold(tokenAddr.Hex(), pc.cfg.USDCAddress.Hex())
}

// getSupportedTokensString returns a string listing all supported tokens
func (pc *PaymasterController) getSupportedTokensString() string {
	return fmt.Sprintf("ETH, %s (USDT), %s (USDC)",
		pc.cfg.USDTAddress.Hex(),
		pc.cfg.USDCAddress.Hex())
}
