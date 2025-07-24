// Package orm provides the ORM layer for managing policies in the Scroll paymaster service.
package orm

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"gorm.io/gorm"
)

// PolicyLimits represents the limits configuration for a policy
type PolicyLimits struct {
	MaxEthPerWalletPerWindow          string `json:"max_eth_per_wallet_per_window"`
	MaxTransactionsPerWalletPerWindow int64  `json:"max_transactions_per_wallet_per_window"`
	TimeWindowHours                   int    `json:"time_window_hours"`
}

// Policy represents the data structure for sponsorship policy
type Policy struct {
	db *gorm.DB `gorm:"column:-"`

	ID         uint64       `gorm:"column:id;primaryKey"`
	APIKeyHash string       `gorm:"column:api_key_hash"`
	PolicyID   int64        `gorm:"column:policy_id"`
	PolicyName string       `gorm:"column:policy_name"`
	Limits     PolicyLimits `gorm:"column:limits;serializer:json"`
	CreatedAt  time.Time    `gorm:"column:created_at"`
	UpdatedAt  time.Time    `gorm:"column:updated_at"`
	DeletedAt  *time.Time   `gorm:"column:deleted_at"`
}

// TableName returns the database table name for Policy
func (*Policy) TableName() string {
	return "policy"
}

// NewPolicy creates a new instance of Policy
func NewPolicy(db *gorm.DB) *Policy {
	return &Policy{db: db}
}

// Create creates a new policy record
func (p *Policy) Create(ctx context.Context, policy *Policy) error {
	return p.db.WithContext(ctx).Create(policy).Error
}

// GetByAPIKeyAndPolicyID retrieves a policy by API key and policy ID
func (p *Policy) GetByAPIKeyAndPolicyID(ctx context.Context, apiKey string, policyID int64) (*Policy, error) {
	var result Policy
	apiKeyHash := crypto.Keccak256Hash([]byte(apiKey)).Hex()
	err := p.db.WithContext(ctx).
		Where("api_key_hash = ?", apiKeyHash).
		Where("policy_id = ?", policyID).
		First(&result).Error
	return &result, err
}

// GetByAPIKey retrieves all policies for a given API key
func (p *Policy) GetByAPIKey(ctx context.Context, apiKey string) ([]*Policy, error) {
	var results []*Policy
	apiKeyHash := crypto.Keccak256Hash([]byte(apiKey)).Hex()
	err := p.db.WithContext(ctx).
		Where("api_key_hash = ?", apiKeyHash).
		Order("policy_id ASC").
		Find(&results).Error
	return results, err
}

// Update updates a policy record
func (p *Policy) Update(ctx context.Context, apiKey string, policyID int64, updates map[string]interface{}) error {
	apiKeyHash := crypto.Keccak256Hash([]byte(apiKey)).Hex()
	return p.db.WithContext(ctx).
		Model(&Policy{}).
		Where("api_key_hash = ?", apiKeyHash).
		Where("policy_id = ?", policyID).
		Updates(updates).Error
}

// Delete soft deletes a policy record
func (p *Policy) Delete(ctx context.Context, apiKey string, policyID int64) error {
	apiKeyHash := crypto.Keccak256Hash([]byte(apiKey)).Hex()
	return p.db.WithContext(ctx).
		Where("api_key_hash = ?", apiKeyHash).
		Where("policy_id = ?", policyID).
		Delete(&Policy{}).Error
}
