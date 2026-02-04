include .env
export

.PHONY: install build test clean
.PHONY: deploy-base deploy-base-sepolia deploy-scroll deploy-scroll-sepolia
.PHONY: deploy-base-trezor deploy-base-sepolia-trezor deploy-scroll-trezor deploy-scroll-sepolia-trezor
.PHONY: verify compute-address

# Default Trezor derivation path (first account)
TREZOR_PATH ?= m/44'/60'/0'/0/0

# Install dependencies
install:
	forge install foundry-rs/forge-std
	forge install OpenZeppelin/openzeppelin-contracts@v5.0.1
	forge install eth-infinitism/account-abstraction@v0.7.0
	forge install Vectorized/solady
	git clone --depth 1 https://github.com/coinbase/verifying-paymaster.git lib/verifying-paymaster || true

# Build contracts
build:
	forge build

# Run tests
test:
	forge test -vvv

# Clean build artifacts
clean:
	forge clean

# Compute expected deployment address (no wallet needed)
compute-address:
	@forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--sig "computeAddress(address,address,bytes32)" \
		$(VERIFYING_SIGNER) $(OWNER) $(or $(DEPLOY_SALT),0x0)

# =============================================================================
# Deploy with private key
# =============================================================================

deploy-base:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url base \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast \
		--verify \
		-vvvv

deploy-base-sepolia:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url base_sepolia \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast \
		--verify \
		-vvvv

deploy-scroll:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url scroll \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast \
		--verify \
		-vvvv

deploy-scroll-sepolia:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url scroll_sepolia \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast \
		--verify \
		-vvvv

# =============================================================================
# Deploy with Trezor hardware wallet
# =============================================================================

deploy-base-trezor:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url base \
		--trezor \
		--mnemonic-derivation-paths "$(TREZOR_PATH)" \
		--broadcast \
		--verify \
		-vvvv

deploy-base-sepolia-trezor:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url base_sepolia \
		--trezor \
		--mnemonic-derivation-paths "$(TREZOR_PATH)" \
		--broadcast \
		--verify \
		-vvvv

deploy-scroll-trezor:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url scroll \
		--trezor \
		--mnemonic-derivation-paths "$(TREZOR_PATH)" \
		--broadcast \
		--verify \
		-vvvv

deploy-scroll-sepolia-trezor:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url scroll_sepolia \
		--trezor \
		--mnemonic-derivation-paths "$(TREZOR_PATH)" \
		--broadcast \
		--verify \
		-vvvv

# =============================================================================
# Deploy with Ledger hardware wallet
# =============================================================================

deploy-base-ledger:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url base \
		--ledger \
		--mnemonic-derivation-paths "$(TREZOR_PATH)" \
		--broadcast \
		--verify \
		-vvvv

deploy-base-sepolia-ledger:
	forge script script/DeployPaymaster.s.sol:DeployPaymaster \
		--rpc-url base_sepolia \
		--ledger \
		--mnemonic-derivation-paths "$(TREZOR_PATH)" \
		--broadcast \
		--verify \
		-vvvv

# =============================================================================
# Verification
# =============================================================================

verify:
	forge verify-contract $(CONTRACT_ADDRESS) \
		src/VerifyingPaymaster.sol:VerifyingPaymaster \
		--constructor-args $$(cast abi-encode "constructor(address,address,address)" 0x0000000071727De22E5E9d8BAf0edAc6f37da032 $(VERIFYING_SIGNER) $(OWNER)) \
		--chain $(CHAIN)
