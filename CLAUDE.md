# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Scroll Paymaster is a Go-based JSON-RPC microservice implementing ERC-7677 paymaster functionality for the Scroll blockchain. It handles user operation sponsorship via configurable policies, gas fee calculations, rate limiting, and API key authentication.

## Build Commands

```bash
make build         # Build binary to build/bin/paymaster
make lint          # Run golangci-lint
make fmt           # Format code (goimports, gofumpt, go mod tidy)
make test          # Run tests with coverage and race detection
make docker        # Build Docker image scrolltech/paymaster:latest
make start-dev     # Start PostgreSQL container and run paymaster locally
make stop-dev      # Stop dev environment
```

## Running Tests

```bash
# Run all tests
make test

# Run a single test
go test -v -race ./internal/controller -run TestPaymasterController
```

Tests use testcontainers-go to spin up PostgreSQL containers automatically.

## Database Commands

```bash
./paymaster --db --db.migrate      # Migrate to latest
./paymaster --db --db.reset        # Reset database
./paymaster --db --db.rollback N   # Rollback N versions
```

## Architecture

**Entry Point**: `cmd/main.go` - CLI app using urfave/cli that initializes config, database, and HTTP server

**Core Controllers** (`internal/controller/`):
- `PaymasterController` - Handles `pm_getPaymasterStubData` and `pm_getPaymasterData` JSON-RPC methods, manages gas estimation, supports both ECDSA and AWS KMS signing
- `AdminController` - CRUD for policies with per-wallet limits (max ETH + transaction counts)
- `UsageController` - Retrieves wallet usage statistics

**Routing** (`internal/route/route.go`):
- `POST /` - Unified JSON-RPC handler with auth and rate limiting
- `GET /api/usage/:address/:policy_id` - Usage statistics

**Database** (`internal/orm/`):
- Uses GORM with PostgreSQL
- Migrations via goose (embedded in `internal/orm/migrate/migrations/`)
- Key models: `Policy` (sponsorship policies), `UserOperation` (tracks operations with upsert logic)

**Middleware** (`internal/middleware/`):
- `AuthMiddleware` - Bearer token API key validation
- `RateLimiter` - Token bucket rate limiter

## Configuration

Config file format is JSON (default: `conf/config.json`). Key fields:
- `api_keys` - Valid API keys for authentication
- `paymaster_address_v7` - Paymaster contract address
- `chain_id` - Target chain ID
- `signer_private_key` or `aws_kms_key_id` - Signing key
- `ethereum_rpc_urls` - Must be Ethereum mainnet (chain ID 1) for gas oracle
- `db_config` - PostgreSQL connection settings

CLI flags: `--config`, `--http.port` (default 8750), `--metrics`, `--metrics.port` (default 6060), `--log.debug`, `--verbosity`

## Key Implementation Notes

- API keys are stored as Keccak256 hashes (no plaintext)
- Gas prices fetched from Chainlink oracle on Ethereum mainnet
- RPC sanity check on startup validates Ethereum mainnet connection (chain ID 1 required)
- AWS KMS signer includes signature malleability checks
- Policies enforce per-wallet time-windowed limits (max ETH amount + transaction count)
