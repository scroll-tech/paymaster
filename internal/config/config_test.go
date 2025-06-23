package config

import (
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		// Create a temporary config file
		configContent := `{
			"api_keys": ["key1", "key2", "key3"],
			"paymaster_address_v7": "0x1234567890123456789012345678901234567890",
			"rate_limiter_qps": 1000,
			"chain_id": 534351,
			"signer_private_key": "0000000000000000000000000000000000000000000000000000000000000000",
			"usdt_address": "0x5c084394b327b48a7e9886b98d6d595c9a83b5ed",
			"ethereum_rpc_urls": [
				"https://ethereum-rpc.publicnode.com",
				"https://eth-mainnet.public.blastapi.io",
				"https://eth.drpc.org"
			],
			"db_config": {
				"driver_name": "postgres",
				"dsn": "postgres://postgres:123456@localhost:5433/paymaster?sslmode=disable",
				"maxOpenNum": 100,
				"maxIdleNum": 20
			}
		}`

		tmpFile, err := os.CreateTemp("", "config_test_*.json")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Test loading the config
		cfg, err := NewConfig(tmpFile.Name())
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify all fields
		assert.Equal(t, []string{"key1", "key2", "key3"}, cfg.APIKeys)
		assert.Equal(t, common.HexToAddress("0x1234567890123456789012345678901234567890"), cfg.PaymasterAddressV7)
		assert.Equal(t, int64(1000), cfg.RateLimiterQPS)
		assert.Equal(t, int64(534351), cfg.ChainID)
		assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", cfg.SignerPrivateKey)
		assert.Equal(t, common.HexToAddress("0x5c084394b327b48a7e9886b98d6d595c9a83b5ed"), cfg.USDTAddress)

		expectedRPCURLs := []string{
			"https://ethereum-rpc.publicnode.com",
			"https://eth-mainnet.public.blastapi.io",
			"https://eth.drpc.org",
		}
		assert.Equal(t, expectedRPCURLs, cfg.EthereumRPCURLs)

		// Verify database config
		assert.Equal(t, "postgres", cfg.DBConfig.DriverName)
		assert.Equal(t, "postgres://postgres:123456@localhost:5433/paymaster?sslmode=disable", cfg.DBConfig.DSN)
		assert.Equal(t, 100, cfg.DBConfig.MaxOpenNum)
		assert.Equal(t, 20, cfg.DBConfig.MaxIdleNum)
	})
}
