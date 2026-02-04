// Script to convert a PEM-encoded secp256k1 public key to an Ethereum address.
// This is useful for deriving the signer address from an AWS KMS key's public key.
//
// Usage:
//   go run scripts/pubkey_to_address.go <base64-encoded-public-key>
//   go run scripts/pubkey_to_address.go --pem <path-to-pem-file>
//
// Example:
//   go run scripts/pubkey_to_address.go "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE6jbMw2dq5p3rJjX59WZHVAx4qLLz6wTaKc+fv7YsIMMf2RHPgM0t+MfmOsHoHlUpKw4TTVqPE8tddHlcqe4OMQ=="
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run scripts/pubkey_to_address.go <base64-encoded-public-key>")
		fmt.Println("  go run scripts/pubkey_to_address.go --pem <path-to-pem-file>")
		os.Exit(1)
	}

	var b64Data string

	if os.Args[1] == "--pem" {
		if len(os.Args) < 3 {
			fmt.Println("Error: --pem requires a file path")
			os.Exit(1)
		}
		pemData, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Printf("Error reading PEM file: %v\n", err)
			os.Exit(1)
		}
		b64Data = extractBase64FromPEM(string(pemData))
	} else {
		b64Data = os.Args[1]
	}

	address, err := pubkeyToAddress(b64Data)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ethereum Address: %s\n", address)
}

func extractBase64FromPEM(pem string) string {
	var b64Lines []string
	scanner := bufio.NewScanner(strings.NewReader(pem))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if line != "" {
			b64Lines = append(b64Lines, line)
		}
	}
	return strings.Join(b64Lines, "")
}

func pubkeyToAddress(b64Data string) (string, error) {
	// Decode base64
	derBytes, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// The ASN.1 DER structure for secp256k1 public key:
	// SEQUENCE {
	//   SEQUENCE { OID ecPublicKey, OID secp256k1 }
	//   BIT STRING (0x04 || X || Y)
	// }
	// The public key (with 0x04 prefix) starts at offset 23
	if len(derBytes) < 88 {
		return "", fmt.Errorf("invalid DER length: expected at least 88 bytes, got %d", len(derBytes))
	}

	pubkeyWithPrefix := derBytes[23:]
	if len(pubkeyWithPrefix) != 65 {
		return "", fmt.Errorf("invalid public key length: expected 65 bytes, got %d", len(pubkeyWithPrefix))
	}

	if pubkeyWithPrefix[0] != 0x04 {
		return "", fmt.Errorf("invalid public key prefix: expected 0x04, got 0x%02x", pubkeyWithPrefix[0])
	}

	// Remove the 0x04 prefix to get 64 bytes (X || Y)
	pubkeyBytes := pubkeyWithPrefix[1:]

	// Keccak256 hash
	hash := crypto.Keccak256(pubkeyBytes)

	// Last 20 bytes = address
	addressBytes := hash[12:]
	addressHex := hex.EncodeToString(addressBytes)

	// EIP-55 checksum
	checksumHash := crypto.Keccak256([]byte(addressHex))
	var checksummed strings.Builder
	checksummed.WriteString("0x")
	for i, c := range addressHex {
		if c >= '0' && c <= '9' {
			checksummed.WriteByte(byte(c))
		} else if checksumHash[i/2]>>(4*(1-uint(i%2)))&0xF >= 8 {
			checksummed.WriteByte(byte(c) - 32) // uppercase
		} else {
			checksummed.WriteByte(byte(c))
		}
	}

	return checksummed.String(), nil
}
