// Package utils provides utility functions for the Scroll paymaster service.
package utils

// IsValidAPIKey checks if the provided API key is valid against the list of allowed keys.
func IsValidAPIKey(apiKey string, allowedKeys []string) bool {
	if apiKey == "" {
		return false
	}

	for _, key := range allowedKeys {
		if apiKey == key {
			return true
		}
	}

	return false
}
