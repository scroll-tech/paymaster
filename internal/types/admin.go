// Package types defines types used in admin operations for the Scroll paymaster service.
package types

import "github.com/scroll-tech/paymaster/internal/orm"

// PolicyResponse represents a policy in API responses
type PolicyResponse struct {
	PolicyID   string           `json:"policy_id"`
	PolicyName string           `json:"policy_name"`
	Limits     orm.PolicyLimits `json:"limits"`
	CreatedAt  string           `json:"created_at"`
	UpdatedAt  string           `json:"updated_at"`
}

// AdminOperationResponse represents the response for admin operations
type AdminOperationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
