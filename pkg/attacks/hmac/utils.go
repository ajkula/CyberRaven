package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// HMAC signature generation utilities

// generateHMAC generates a proper HMAC signature
func generateHMAC(endpoint, method string, timestamp time.Time, targetConfig *config.TargetConfig) string {
	if targetConfig.Auth.HMAC.Secret == "" {
		return ""
	}

	message := fmt.Sprintf("%s\n%s\n%d", method, endpoint, timestamp.Unix())

	var h func() hash.Hash
	switch strings.ToLower(targetConfig.Auth.HMAC.Algorithm) {
	case "sha512":
		h = sha512.New
	default:
		h = sha256.New
	}

	mac := hmac.New(h, []byte(targetConfig.Auth.HMAC.Secret))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature)
}

// generateInvalidHMAC generates an invalid HMAC signature
func generateInvalidHMAC(testCount int) string {
	invalid := []string{
		hex.EncodeToString([]byte("invalid_signature_123456789")),
		base64.StdEncoding.EncodeToString([]byte("fake_signature")),
		"0123456789abcdef" + hex.EncodeToString([]byte("wrong")),
	}

	index := testCount % len(invalid)
	return invalid[index]
}

// buildHMACHeaders creates standard HMAC headers
func buildHMACHeaders(signature string, timestamp time.Time, targetConfig *config.TargetConfig) map[string]string {
	headers := map[string]string{}

	if targetConfig.Auth.HMAC.SignatureHeader != "" && signature != "" {
		headers[targetConfig.Auth.HMAC.SignatureHeader] = signature
	}

	if targetConfig.Auth.HMAC.TimestampHeader != "" {
		headers[targetConfig.Auth.HMAC.TimestampHeader] = strconv.FormatInt(timestamp.Unix(), 10)
	}

	return headers
}

// Default configuration functions

func getDefaultHMACEndpoints() []string {
	return []string{
		"/api/authenticate", "/api/auth", "/api/login",
		"/api/user", "/api/profile", "/api/account",
		"/api/admin", "/api/secure", "/api/protected",
		"/webhook", "/api/webhook", "/callback",
	}
}

func getDefaultHMACSecrets() []string {
	return []string{
		"secret", "key", "password", "hmac_secret",
		"your-secret-key", "shared_secret", "api_key",
		"webhook_secret", "signing_key", "auth_secret",
	}
}

// Timing analysis utilities

func calculateAverage(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range times {
		total += t
	}
	return total / time.Duration(len(times))
}

func analyzeTimingDifference(validTimes, invalidTimes []time.Duration) (time.Duration, bool) {
	if len(validTimes) < 5 || len(invalidTimes) < 5 {
		return 0, false
	}

	validAvg := calculateAverage(validTimes)
	invalidAvg := calculateAverage(invalidTimes)

	timeDiff := validAvg - invalidAvg
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	threshold := time.Duration(float64(validAvg) * 0.2)
	if threshold < 10*time.Millisecond {
		threshold = 10 * time.Millisecond
	}

	isVulnerable := timeDiff > threshold
	return timeDiff, isVulnerable
}

// Algorithm mapping utilities

func getAlgorithmMapping() map[string]func() hash.Hash {
	return map[string]func() hash.Hash{
		"sha256": sha256.New,
		"sha512": sha512.New,
	}
}
