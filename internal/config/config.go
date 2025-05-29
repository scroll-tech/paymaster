package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/scroll-tech/go-ethereum/common"
)

// Config represents the configuration for the paymaster.
type Config struct {
	APIKey             string         `json:"api_key"`
	PaymasterAddressV7 common.Address `json:"paymaster_address_v7"`
	RateLimiterQPS     int64          `json:"rate_limiter_qps"`
	ChainID            int64          `json:"chain_id"`
	SignerPrivateKey   string         `json:"signer_private_key"`
	USDTAddress        common.Address `json:"usdt_address"`
	EthereumRPCURLs    []string       `json:"ethereum_rpc_urls"`
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
