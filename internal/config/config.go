// Package config provides the configuration for the Scroll paymaster service.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"

	"github.com/scroll-tech/paymaster/internal/utils/database"
)

// Config represents the configuration for the paymaster.
type Config struct {
	APIKeys            []string        `json:"api_keys"`
	PaymasterAddressV7 common.Address  `json:"paymaster_address_v7"`
	RateLimiterQPS     int64           `json:"rate_limiter_qps"`
	ChainID            int64           `json:"chain_id"`
	SignerPrivateKey   string          `json:"signer_private_key"`
	USDTAddress        common.Address  `json:"usdt_address"`
	EthereumRPCURLs    []string        `json:"ethereum_rpc_urls"`
	DBConfig           database.Config `json:"db_config"`
}

// NewConfig return an unmarshalled config instance.
func NewConfig(file string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	cfg := Config{}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
