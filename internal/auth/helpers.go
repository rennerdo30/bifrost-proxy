package auth

import (
	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the cost factor for bcrypt hashing.
// Per security guidelines, this should be at least 12.
const bcryptCost = 12

// HashPassword creates a bcrypt hash of a password.
// This is a convenience function for creating password hashes.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
