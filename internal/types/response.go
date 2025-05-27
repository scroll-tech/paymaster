package types

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// Success shows OK.
	Success = 0
	// InternalServerError shows a fatal error in the server
	InternalServerError = 500

	// JSON-RPC Standard Errors

	// ParseErrorCode indicates a JSON parsing error
	ParseErrorCode = -32700
	// InvalidRequestCode indicates an invalid JSON-RPC request
	InvalidRequestCode = -32600
	// MethodNotFoundCode indicates that the requested method does not exist
	MethodNotFoundCode = -32601
	// InvalidParamsCode indicates that the parameters provided to the method are invalid
	InvalidParamsCode = -32602

	// Custom Paymaster Errors

	// UnauthorizedErrorCode indicates that the user is not authorized to perform the action
	UnauthorizedErrorCode = -32000
	// UnsupportedChainIDCode indicates that the chain ID is not supported by the paymaster
	UnsupportedChainIDCode = -32001
	// UnsupportedEntryPointCode indicates that the entry point is not supported by the paymaster
	UnsupportedEntryPointCode = -32002
	// PaymasterDataGenErrorCode indicates an error in generating paymaster data
	PaymasterDataGenErrorCode = -32003
	// UnsupportedTokenErrorCode indicates that the token is not supported by the paymaster
	UnsupportedTokenErrorCode = -32004

	// JSONRPCVersion is the version of JSON-RPC used
	JSONRPCVersion = "2.0"
)

// Response the response schema
type Response struct {
	ErrCode int         `json:"errcode"`
	ErrMsg  string      `json:"errmsg"`
	Data    interface{} `json:"data"`
}

// RenderJSON renders response with json
func RenderJSON(ctx *gin.Context, errCode int, err error, data interface{}) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	renderData := Response{
		ErrCode: errCode,
		ErrMsg:  errMsg,
		Data:    data,
	}
	ctx.JSON(http.StatusOK, renderData)
}

// RenderSuccess renders success response with json
func RenderSuccess(ctx *gin.Context, data interface{}) {
	RenderJSON(ctx, Success, nil, data)
}

// SendError sends a JSON-RPC error response
func SendError(c *gin.Context, id interface{}, code int, message string) {
	errResp := RPCError{Code: code, Message: message}
	c.JSON(http.StatusOK, PaymasterJSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error:   &errResp,
	})
}

// SendSuccess sends a JSON-RPC success response
func SendSuccess(c *gin.Context, id interface{}, result interface{}) {
	c.JSON(http.StatusOK, PaymasterJSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	})
}
