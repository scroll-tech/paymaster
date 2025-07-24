// Package orm provides the ORM layer for managing user operations in the Scroll paymaster service.
package orm

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserOperationStatus represents the status of a user operation
type UserOperationStatus int

const (
	// UserOperationStatusPaymasterStubDataProvided is the status when pm_getPaymasterStubData is called
	UserOperationStatusPaymasterStubDataProvided UserOperationStatus = 1
	// UserOperationStatusPaymasterDataProvided is the status when pm_getPaymasterData is called
	UserOperationStatusPaymasterDataProvided UserOperationStatus = 2
)

// UserOperation represents the data structure for user operation
type UserOperation struct {
	db *gorm.DB `gorm:"column:-"`

	ID         uint64              `gorm:"column:id;primaryKey"`
	APIKeyHash string              `gorm:"column:api_key_hash;uniqueIndex:unique_idx_api_key_hash_policy_id_sender_nonce"`
	PolicyID   int64               `gorm:"column:policy_id;uniqueIndex:unique_idx_api_key_hash_policy_id_sender_nonce"`
	Sender     string              `gorm:"column:sender;uniqueIndex:unique_idx_api_key_hash_policy_id_sender_nonce"`
	Nonce      int64               `gorm:"column:nonce;uniqueIndex:unique_idx_api_key_hash_policy_id_sender_nonce"`
	WeiAmount  int64               `gorm:"column:wei_amount"`
	Status     UserOperationStatus `gorm:"column:status"`
	CreatedAt  time.Time           `gorm:"column:created_at"`
	UpdatedAt  time.Time           `gorm:"column:updated_at"`
	DeletedAt  *time.Time          `gorm:"column:deleted_at"`
}

// TableName returns the database table name for UserOperation
func (*UserOperation) TableName() string {
	return "user_operation"
}

// NewUserOperation creates a new instance of UserOperation
func NewUserOperation(db *gorm.DB) *UserOperation {
	return &UserOperation{db: db}
}

// CreateOrUpdate creates a new user operation or updates existing one with max wei_amount
func (u *UserOperation) CreateOrUpdate(ctx context.Context, userOp *UserOperation) error {
	return u.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "api_key_hash"},
				{Name: "policy_id"},
				{Name: "sender"},
				{Name: "nonce"},
			},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"wei_amount": gorm.Expr("CASE WHEN EXCLUDED.wei_amount > user_operation.wei_amount THEN EXCLUDED.wei_amount ELSE user_operation.wei_amount END"),
				"status":     gorm.Expr("EXCLUDED.status"),
			}),
		}).
		Create(userOp).Error
}

// WalletUsageStats represents the usage statistics for a wallet
type WalletUsageStats struct {
	TransactionCount        int64      `json:"transaction_count" gorm:"column:count"`
	TotalWeiAmount          int64      `json:"total_wei_amount" gorm:"column:total_wei_amount"`
	EarliestTransactionTime *time.Time `json:"earliest_transaction_time,omitempty" gorm:"column:earliest_transaction_time"`
}

// GetWalletUsageStats gets both transaction count and total wei amount in a single query
func (u *UserOperation) GetWalletUsageStats(ctx context.Context, apiKey string, policyID int64, sender string, timeWindowHours int) (*WalletUsageStats, error) {
	// Use a temporary struct to handle SQLite string time type
	var tempResult struct {
		Count          int64  `gorm:"column:count"`
		TotalWeiAmount int64  `gorm:"column:total_wei_amount"`
		EarliestTime   string `gorm:"column:earliest_transaction_time"`
	}

	apiKeyHash := crypto.Keccak256Hash([]byte(apiKey)).Hex()
	timeThreshold := time.Now().UTC().Add(time.Duration(-timeWindowHours) * time.Hour)

	if err := u.db.WithContext(ctx).
		Model(&UserOperation{}).
		Select("COUNT(*) as count, COALESCE(SUM(wei_amount), 0) as total_wei_amount, MIN(updated_at) as earliest_transaction_time").
		Where("api_key_hash = ?", apiKeyHash).
		Where("policy_id = ?", policyID).
		Where("sender = ?", sender).
		Where("updated_at >= ?", timeThreshold).
		Scan(&tempResult).Error; err != nil {
		return nil, err
	}

	result := &WalletUsageStats{
		TransactionCount: tempResult.Count,
		TotalWeiAmount:   tempResult.TotalWeiAmount,
	}

	if tempResult.EarliestTime != "" {
		if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", tempResult.EarliestTime); err == nil {
			result.EarliestTransactionTime = &parsedTime
		} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", tempResult.EarliestTime); err == nil {
			result.EarliestTransactionTime = &parsedTime
		}
	}

	return result, nil
}
