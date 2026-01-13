package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerifyChecksum verifies the SHA256 checksum of a file.
func VerifyChecksum(filePath, expectedHash string) error {
	actualHash, err := CalculateChecksum(filePath)
	if err != nil {
		return fmt.Errorf("calculate checksum: %w", err)
	}

	// Normalize hashes to lowercase for comparison
	expectedHash = strings.ToLower(strings.TrimSpace(expectedHash))
	actualHash = strings.ToLower(actualHash)

	if actualHash != expectedHash {
		return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expectedHash, actualHash)
	}

	return nil
}

// CalculateChecksum calculates the SHA256 hash of a file.
func CalculateChecksum(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ParseChecksumFile parses a checksums.txt file.
// Format: "<hash>  <filename>" (two spaces between hash and filename)
func ParseChecksumFile(content string) (map[string]string, error) {
	checksums := make(map[string]string)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle both single and double space separators
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		hash := parts[0]
		filename := parts[len(parts)-1] // Last field is the filename

		// Validate hash looks like SHA256 (64 hex chars)
		if len(hash) != 64 {
			continue
		}

		checksums[filename] = hash
	}

	if len(checksums) == 0 {
		return nil, fmt.Errorf("no valid checksums found")
	}

	return checksums, nil
}
