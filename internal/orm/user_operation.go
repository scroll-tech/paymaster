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
	// UserOperationStatusPaymasterStubDataProvided is the status when pm_getPaymasterStubData is called
	UserOperationStatusPaymasterStubDataProvided UserOperationStatus = 1
	// UserOperationStatusPaymasterDataProvided is the status when pm_getPaymasterData is called
	UserOperationStatusPaymasterDataProvided UserOperationStatus = 2
)

// UserOperation represents the data structure for user operation
type UserOperation struct {
	db *gorm.DB `gorm:"column:-"`

	ID        uint64              `gorm:"column:id;primaryKey"`
	APIKey    string              `gorm:"column:api_key;uniqueIndex:unique_idx_api_key_policy_id_sender_nonce"`
	PolicyID  int64               `gorm:"column:policy_id;uniqueIndex:unique_idx_api_key_policy_id_sender_nonce"`
	Sender    string              `gorm:"column:sender;uniqueIndex:unique_idx_api_key_policy_id_sender_nonce"`
	Nonce     int64               `gorm:"column:nonce;uniqueIndex:unique_idx_api_key_policy_id_sender_nonce"`
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
			Columns: []clause.Column{
				{Name: "api_key"},
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

// GetWalletUsage calculates the ETH amount used by a specific sender within the time window for a specific policy
func (u *UserOperation) GetWalletUsage(ctx context.Context, apiKey string, policyID int64, sender string, timeWindowHours int) (int64, error) {
	var usage int64
	err := u.db.WithContext(ctx).
		Model(&UserOperation{}).
		Select("COALESCE(SUM(wei_amount), 0)").
		Where("api_key = ?", apiKey).
		Where("policy_id = ?", policyID).
		Where("sender = ?", sender).
		Where("updated_at >= ?", time.Now().UTC().Add(time.Duration(-timeWindowHours)*time.Hour)).
		Scan(&usage).Error

	return usage, err
}
