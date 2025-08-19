package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidAPIKey(t *testing.T) {
	allowedKeys := []string{"key1", "key2", "key3"}

	t.Run("ValidKey", func(t *testing.T) {
		assert.True(t, IsValidAPIKey("key1", allowedKeys))
		assert.True(t, IsValidAPIKey("key2", allowedKeys))
		assert.True(t, IsValidAPIKey("key3", allowedKeys))
	})

	t.Run("InvalidKey", func(t *testing.T) {
		assert.False(t, IsValidAPIKey("invalid", allowedKeys))
		assert.False(t, IsValidAPIKey("key4", allowedKeys))
	})

	t.Run("EmptyKey", func(t *testing.T) {
		assert.False(t, IsValidAPIKey("", allowedKeys))
	})

	t.Run("EmptyAllowedKeys", func(t *testing.T) {
		assert.False(t, IsValidAPIKey("key1", []string{}))
	})

	t.Run("NilAllowedKeys", func(t *testing.T) {
		assert.False(t, IsValidAPIKey("key1", nil))
	})
}
