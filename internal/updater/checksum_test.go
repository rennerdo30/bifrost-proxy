package updater

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateChecksum(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create test file
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Calculate checksum
	hash, err := CalculateChecksum(testFile)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA256 hex is 64 chars
}

func TestCalculateChecksum_FileNotFound(t *testing.T) {
	_, err := CalculateChecksum("/nonexistent/file")
	assert.Error(t, err)
}

func TestVerifyChecksum(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create test file
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Calculate expected hash
	expectedHash, err := CalculateChecksum(testFile)
	require.NoError(t, err)

	// Verify with correct hash
	err = VerifyChecksum(testFile, expectedHash)
	assert.NoError(t, err)

	// Verify with incorrect hash
	err = VerifyChecksum(testFile, "0000000000000000000000000000000000000000000000000000000000000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum verification failed")
}

func TestVerifyChecksum_CaseInsensitive(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create test file
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Calculate expected hash
	expectedHash, err := CalculateChecksum(testFile)
	require.NoError(t, err)

	// Verify with uppercase hash (will fail but should handle case conversion)
	upperHash := "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
	err = VerifyChecksum(testFile, upperHash)
	// Should fail with wrong hash
	assert.Error(t, err)

	// Verify with lowercase hash (correct)
	err = VerifyChecksum(testFile, expectedHash)
	assert.NoError(t, err)
}

func TestParseChecksumFile(t *testing.T) {
	content := `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  file1.txt
fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  file2.txt
`

	checksums, err := ParseChecksumFile(content)
	require.NoError(t, err)
	assert.Len(t, checksums, 2)
	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", checksums["file1.txt"])
	assert.Equal(t, "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", checksums["file2.txt"])
}

func TestParseChecksumFile_Empty(t *testing.T) {
	_, err := ParseChecksumFile("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid checksums found")
}

func TestParseChecksumFile_InvalidLines(t *testing.T) {
	content := `invalid line
too short
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  valid.txt
`

	checksums, err := ParseChecksumFile(content)
	require.NoError(t, err)
	assert.Len(t, checksums, 1)
	assert.Contains(t, checksums, "valid.txt")
}

func TestParseChecksumFile_Whitespace(t *testing.T) {
	content := `  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef    file.txt  `

	checksums, err := ParseChecksumFile(content)
	require.NoError(t, err)
	assert.Len(t, checksums, 1)
	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", checksums["file.txt"])
}
