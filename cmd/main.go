package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/scroll-tech/go-ethereum/log"
	"github.com/urfave/cli/v2"

	"github.com/scroll-tech/paymaster/internal/config"
	"github.com/scroll-tech/paymaster/internal/controller"
	"github.com/scroll-tech/paymaster/internal/route"
	"github.com/scroll-tech/paymaster/internal/utils"
	"github.com/scroll-tech/paymaster/internal/utils/observability"
)

func action(ctx *cli.Context) error {
	// Load config file.
	cfgFile := ctx.String(utils.ConfigFileFlag.Name)
	cfg, err := config.NewConfig(cfgFile)
	if err != nil {
		log.Crit("failed to load config file", "config file", cfgFile, "error", err)
	}

	// Perform RPC sanity check
	if err = performRPCSanityCheck(cfg); err != nil {
		log.Crit("RPC sanity check failed", "error", err)
	}

	observability.Server(ctx)

	router := gin.New()
	controller.InitAPI(cfg)
	route.Route(router, cfg)
	port := ctx.String(utils.HTTPPortFlag.Name)
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if runServerErr := srv.ListenAndServe(); runServerErr != nil && !errors.Is(runServerErr, http.ErrServerClosed) {
			log.Crit("run coordinator http server failure", "error", runServerErr)
		}
	}()

	log.Info("Start paymaster success...", "version", utils.Version)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	<-interrupt

	log.Info("Start shutdown paymaster server...")

	closeCtx, cancelExit := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelExit()
	if err = srv.Shutdown(closeCtx); err != nil {
		log.Warn("shutdown paymaster server failure", "error", err)
		return nil
	}

	<-closeCtx.Done()
	log.Info("paymaster server exiting success")
	return nil
}

// performRPCSanityCheck tests each RPC URL with eth_chainId
func performRPCSanityCheck(cfg *config.Config) error {
	log.Info("Performing RPC sanity check...")

	if len(cfg.EthereumRPCURLs) == 0 {
		return fmt.Errorf("no Ethereum RPC URLs configured")
	}

	for i, rpcURL := range cfg.EthereumRPCURLs {
		log.Info("Testing RPC endpoint", "index", i+1, "url", rpcURL)

		// Basic URL validation
		if rpcURL == "" {
			return fmt.Errorf("RPC URL %d is empty", i+1)
		}

		if !strings.HasPrefix(rpcURL, "http://") && !strings.HasPrefix(rpcURL, "https://") {
			return fmt.Errorf("RPC URL %d has invalid format: %s", i+1, rpcURL)
		}

		// Test eth_chainId
		client := &http.Client{Timeout: 10 * time.Second}

		payload := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "eth_chainId",
			"params":  []interface{}{},
			"id":      1,
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal eth_chainId request for RPC %d (%s): %w", i+1, rpcURL, err)
		}

		resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to connect to RPC %d (%s): %w", i+1, rpcURL, err)
		}

		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", "rpc", rpcURL, "error", closeErr)
		}
		if err != nil {
			return fmt.Errorf("failed to read response from RPC %d (%s): %w", i+1, rpcURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("RPC %d (%s) returned HTTP error: %d %s", i+1, rpcURL, resp.StatusCode, resp.Status)
		}

		var rpcResponse struct {
			Result string `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}

		if err := json.Unmarshal(body, &rpcResponse); err != nil {
			return fmt.Errorf("failed to parse response from RPC %d (%s): %w", i+1, rpcURL, err)
		}

		if rpcResponse.Error != nil {
			return fmt.Errorf("RPC %d (%s) returned error: %s", i+1, rpcURL, rpcResponse.Error.Message)
		}

		// Parse and validate chain ID
		chainIDHex := rpcResponse.Result
		if len(chainIDHex) >= 2 && chainIDHex[:2] == "0x" {
			chainIDHex = chainIDHex[2:]
		}

		chainID, ok := new(big.Int).SetString(chainIDHex, 16)
		if !ok {
			return fmt.Errorf("failed to parse chainId from RPC %d (%s): %s", i+1, rpcURL, rpcResponse.Result)
		}

		// Check if the chain ID matches Ethereum mainnet (1)
		// Because paymaster uses gas oracle of Chainlink deployed on Ethereum mainnet.
		if chainID.Int64() != 1 {
			return fmt.Errorf("chain ID mismatch for RPC %d (%s): got %d, expected Ethereum mainnet (1)", i+1, rpcURL, chainID.Int64())
		}

		log.Info("RPC endpoint verified", "index", i+1, "url", rpcURL, "chainId", chainID.Int64())
	}

	log.Info("All RPC endpoints verified successfully", "count", len(cfg.EthereumRPCURLs))
	return nil
}

// Run event watcher cmd instance.
func main() {
	app := cli.NewApp()
	app.Action = action
	app.Name = "api"
	app.Usage = "The Scroll paymaster"
	app.Version = utils.Version
	app.Flags = append(app.Flags, utils.CommonFlags...)
	app.Commands = []*cli.Command{}
	app.Before = func(ctx *cli.Context) error {
		return utils.LogSetup(ctx)
	}

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
