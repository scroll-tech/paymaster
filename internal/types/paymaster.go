package types

import (
	"encoding/json"
	"math/big"

	"github.com/scroll-tech/go-ethereum/common"
)

// PaymasterJSONRPCRequest represents a JSON-RPC request specific to the paymaster service.
type PaymasterJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"` // Method parameters, an array for ERC-7677.
	ID      interface{}     `json:"id,omitempty"`
	APIKey  string          `json:"apiKey"`
}

// PaymasterJSONRPCResponse represents a JSON-RPC response specific to the paymaster service.
type PaymasterJSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"` // Using the same RPCError struct
	ID      interface{} `json:"id"`
}

// RPCError represents a JSON-RPC error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// PaymasterUserOperationV7 defines the UserOperation structure sent to paymaster methods (unsigned),
// when the context implies an EntryPoint v0.7 interaction.
type PaymasterUserOperationV7 struct {
	Sender               common.Address `json:"sender"`
	Nonce                *big.Int       `json:"nonce"`
	InitCode             string         `json:"initCode"`
	CallData             string         `json:"callData"`
	CallGasLimit         *big.Int       `json:"callGasLimit"`
	VerificationGasLimit *big.Int       `json:"verificationGasLimit"`
	PreVerificationGas   *big.Int       `json:"preVerificationGas"`
	MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
}

// GetPaymasterStubDataResultV7 is the result for pm_getPaymasterStubData (EntryPoint v0.7).
type GetPaymasterStubDataResultV7 struct {
	Paymaster                     common.Address `json:"paymaster"`
	PaymasterData                 string         `json:"paymasterData"`
	PaymasterVerificationGasLimit string         `json:"paymasterVerificationGasLimit,omitempty"` // Optional for v0.7
	PaymasterPostOpGasLimit       string         `json:"paymasterPostOpGasLimit"`                 // Required for v0.7, because paymaster cannot trust the wallet side to provide it
}

// GetPaymasterDataResultV7 is the result for pm_getPaymasterData (EntryPoint v0.7).
type GetPaymasterDataResultV7 struct {
	Paymaster     common.Address `json:"paymaster"`
	PaymasterData string         `json:"paymasterData"`
}
