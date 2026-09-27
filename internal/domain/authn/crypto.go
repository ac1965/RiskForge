package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// tokenPrefix marks a string as a RiskForge bearer token (ADR 0012),
// distinguishing it at a glance from other secrets in logs or config.
const tokenPrefix = "rf_"

// GenerateRawToken returns a new random bearer token in the
// "rf_<32 random bytes, base64url-encoded>" form (ADR 0012). This raw
// value is returned to the caller exactly once, at issuance; RiskForge
// never stores or reconstructs it afterward — only HashToken's output is
// persisted (see APIToken.TokenHash).
func GenerateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authn: generate token: %w", err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex-encoded SHA-256 hash of raw, for storage in
// APIToken.TokenHash and for looking a presented bearer token back up.
// RiskForge never logs or persists the raw token itself (AGENTS.md §31).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
