// Package orm provides the ORM layer for managing user operations in the Scroll paymaster service.
package orm

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserOperationStatus represents the status of a user operation
type UserOperationStatus int

const (
	// UserOperationStatusStubDataProvided is the status when pm_getPaymasterStubData is called
	UserOperationStatusStubDataProvided UserOperationStatus = 1
	// UserOperationStatusPaymasterDataProvided is the status when pm_getPaymasterData is called
	UserOperationStatusPaymasterDataProvided UserOperationStatus = 2
)

// UserOperation represents the data structure for user operation
type UserOperation struct {
	db *gorm.DB `gorm:"column:-"`

	ID        uint64              `gorm:"column:id;primaryKey"`
	APIKey    string              `gorm:"column:api_key"`
	PolicyID  int64               `gorm:"column:policy_id"`
	Sender    string              `gorm:"column:sender;uniqueIndex:unique_sender_nonce"`
	Nonce     int64               `gorm:"column:nonce;uniqueIndex:unique_sender_nonce"`
	WeiAmount int64               `gorm:"column:wei_amount"`
	Status    UserOperationStatus `gorm:"column:status"`
	CreatedAt time.Time           `gorm:"column:created_at"`
	UpdatedAt time.Time           `gorm:"column:updated_at"`
	DeletedAt *time.Time          `gorm:"column:deleted_at"`
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
			Columns: []clause.Column{{Name: "sender"}, {Name: "nonce"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"wei_amount": gorm.Expr("CASE WHEN EXCLUDED.wei_amount > user_operation.wei_amount THEN EXCLUDED.wei_amount ELSE user_operation.wei_amount END"),
				"status":     gorm.Expr("EXCLUDED.status"),
			}),
		}).
		Create(userOp).Error
}

// GetWalletUsage calculates the ETH amount used by a specific sender within the time window
func (u *UserOperation) GetWalletUsage(ctx context.Context, apiKey string, sender string, timeWindowHours int) (int64, error) {
	var usage int64
	err := u.db.WithContext(ctx).
		Model(&UserOperation{}).
		Select("COALESCE(SUM(wei_amount), 0)").
		Where("api_key = ?", apiKey).
		Where("sender = ?", sender).
		Where("updated_at >= ?", time.Now().UTC().Add(time.Duration(-timeWindowHours)*time.Hour)).
		Scan(&usage).Error

	return usage, err
}

// GetBySenderAndNonce retrieves user operations by sender and nonce
// NOTE: This function is intended for testing purposes only
func (u *UserOperation) GetBySenderAndNonce(ctx context.Context, apiKey string, sender string, nonce int64) ([]*UserOperation, error) {
	var results []*UserOperation
	if err := u.db.WithContext(ctx).
		Where("api_key = ?", apiKey).
		Where("sender = ?", sender).
		Where("nonce = ?", nonce).
		Find(&results).Error; err != nil {
		return nil, err
	}

	// Set db instance for each result
	for _, result := range results {
		result.db = u.db
	}

	return results, nil
}
