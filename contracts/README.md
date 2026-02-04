# Paymaster Contract Deployment

Foundry-based deployment suite for the VerifyingPaymaster contract.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

## Setup

```bash
cd contracts
make install
cp .env.example .env
# Edit .env with your values
```

## Deriving Signer Address from KMS Public Key

If using AWS KMS for signing, derive the Ethereum address from your KMS key's public key:

```bash
# From the paymaster repo root
go run scripts/pubkey_to_address.go "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE..."

# Or from a PEM file
go run scripts/pubkey_to_address.go --pem /path/to/pubkey.pem
```

Use the output address as `VERIFYING_SIGNER` in your `.env`.

## Deployment

### With Trezor (recommended)

```bash
# Deploy to Base Sepolia (testnet)
make deploy-base-sepolia-trezor

# Deploy to Base mainnet
make deploy-base-trezor

# Deploy to Scroll networks
make deploy-scroll-sepolia-trezor
make deploy-scroll-trezor
```

Your Trezor will prompt you to confirm the transaction. Default derivation path is `m/44'/60'/0'/0/0`. To use a different account:

```bash
make deploy-base-sepolia-trezor
```

### With Ledger

```bash
make deploy-base-sepolia-ledger
```

### With Private Key

```bash
make deploy-base-sepolia
```

## Contract Addresses

The contract uses CREATE2 via Safe Singleton Factory for deterministic addresses. The same constructor args and salt will produce the same address on any chain.

To compute the expected address before deployment:

```bash
make compute-address
```

## Post-Deployment (TODO)

After deploying the paymaster contract:

1. **Fund the paymaster** - Send ETH to the paymaster address. It will auto-deposit to EntryPoint.

2. **Update service config** - Set `paymaster_address_v7` in your paymaster service config to the deployed address.

3. **Configure bundler allowlist** (optional) - If restricting bundlers, call `updateBundlerAllowlist()` on the contract.

## Contract Reference

The VerifyingPaymaster is from [coinbase/verifying-paymaster](https://github.com/coinbase/verifying-paymaster).

Key functions:
- `verifyingSigner` - Address that signs paymaster data (your KMS-derived address)
- `owner` - Can rotate signer, withdraw funds, manage bundler allowlist
- `setPendingVerifyingSigner` + `rotateVerifyingSigner` - Two-step signer rotation
- `updateBundlerAllowlist` - Manage allowed bundlers
