package main

import (
	"regexp"
	"strings"
	"sync"
)

// TLSDLPMatch represents a DLP pattern match found in captured TLS plaintext.
type TLSDLPMatch struct {
	PatternID   string
	PatternName string
	Description string
	Level       string // "high", "critical"
	Score       int
	MitreATTCK  string
	Redacted    string // redacted indicator (first4...last4)
}

// tlsDLPPattern defines a DLP detection pattern for TLS plaintext.
type tlsDLPPattern struct {
	id          string
	name        string
	description string
	pattern     *regexp.Regexp
	level       string
	score       int
	mitre       string
	validator   func(string) bool
}

// TLSDLPMatcher scans TLS plaintext for sensitive data patterns.
type TLSDLPMatcher struct {
	patterns []*tlsDLPPattern
	stats    struct {
		scansPerformed int64
		matchesFound   int64
	}
	statsMu sync.Mutex
}

// NewTLSDLPMatcher creates a matcher with the default DLP pattern set.
func NewTLSDLPMatcher() *TLSDLPMatcher {
	m := &TLSDLPMatcher{}
	m.loadPatterns()
	return m
}

func (m *TLSDLPMatcher) loadPatterns() {
	m.patterns = []*tlsDLPPattern{
		// Credit card numbers (Luhn-validated)
		{
			id:          "tls-dlp-cc-visa",
			name:        "Credit card (Visa)",
			description: "Visa credit card number detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),
			level:       "high",
			score:       85,
			mitre:       "T1048",
			validator:   tlsLuhnCheck,
		},
		{
			id:          "tls-dlp-cc-mc",
			name:        "Credit card (Mastercard)",
			description: "Mastercard credit card number detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b`),
			level:       "high",
			score:       85,
			mitre:       "T1048",
			validator:   tlsLuhnCheck,
		},
		{
			id:          "tls-dlp-cc-amex",
			name:        "Credit card (Amex)",
			description: "American Express card number detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\b3[47][0-9]{13}\b`),
			level:       "high",
			score:       85,
			mitre:       "T1048",
			validator:   tlsLuhnCheck,
		},
		{
			id:          "tls-dlp-cc-disc",
			name:        "Credit card (Discover)",
			description: "Discover card number detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`),
			level:       "high",
			score:       85,
			mitre:       "T1048",
			validator:   tlsLuhnCheck,
		},

		// US SSN
		{
			id:          "tls-dlp-ssn",
			name:        "US Social Security Number",
			description: "US SSN detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			level:       "high",
			score:       90,
			mitre:       "T1048",
			validator:   tlsValidateSSN,
		},

		// AWS credentials
		{
			id:          "tls-dlp-aws-key",
			name:        "AWS Access Key ID",
			description: "AWS access key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.001",
		},
		{
			id:          "tls-dlp-aws-secret",
			name:        "AWS Secret Access Key",
			description: "AWS secret key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.001",
		},

		// GitHub tokens
		{
			id:          "tls-dlp-gh-pat",
			name:        "GitHub PAT",
			description: "GitHub personal access token detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\bgh[ps]_[A-Za-z0-9_]{36,}\b`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.001",
		},
		{
			id:          "tls-dlp-gh-oauth",
			name:        "GitHub OAuth token",
			description: "GitHub OAuth token detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\bgho_[A-Za-z0-9_]{36,}\b`),
			level:       "critical",
			score:       90,
			mitre:       "T1552.001",
		},

		// Stripe
		{
			id:          "tls-dlp-stripe-secret",
			name:        "Stripe live secret key",
			description: "Stripe live secret key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.001",
		},

		// Private keys
		{
			id:          "tls-dlp-pkey-rsa",
			name:        "RSA private key",
			description: "RSA private key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.004",
		},
		{
			id:          "tls-dlp-pkey-ec",
			name:        "EC private key",
			description: "EC private key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.004",
		},
		{
			id:          "tls-dlp-pkey-openssh",
			name:        "OpenSSH private key",
			description: "OpenSSH private key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.004",
		},
		{
			id:          "tls-dlp-pkey-generic",
			name:        "Generic private key",
			description: "Private key detected in TLS plaintext",
			pattern:     regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			level:       "critical",
			score:       95,
			mitre:       "T1552.004",
		},

		// Credentials in URLs
		{
			id:          "tls-dlp-cred-url",
			name:        "Credentials in URL",
			description: "Credentials embedded in URL detected in TLS plaintext",
			pattern:     regexp.MustCompile(`(?i)(?:https?|ftp)://[^:@/\s]+:[^:@/\s]+@[^/\s]+`),
			level:       "high",
			score:       80,
			mitre:       "T1552.001",
		},

		// Generic API key patterns
		{
			id:          "tls-dlp-apikey",
			name:        "Generic API key",
			description: "API key or secret detected in TLS plaintext",
			pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"][A-Za-z0-9\-_.]{20,}['"]`),
			level:       "high",
			score:       75,
			mitre:       "T1552.001",
		},

		// Slack tokens
		{
			id:          "tls-dlp-slack",
			name:        "Slack token",
			description: "Slack bot/user token detected in TLS plaintext",
			pattern:     regexp.MustCompile(`\bxox[bpors]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`),
			level:       "high",
			score:       85,
			mitre:       "T1552.001",
		},
	}
}

// Scan checks the given data for DLP matches and returns any findings.
// It caps matches at 5 per scan to avoid excessive processing.
func (m *TLSDLPMatcher) Scan(data []byte) []TLSDLPMatch {
	m.statsMu.Lock()
	m.stats.scansPerformed++
	m.statsMu.Unlock()

	text := string(data)
	var matches []TLSDLPMatch

	for _, p := range m.patterns {
		found := p.pattern.FindAllString(text, 3)
		for _, match := range found {
			if p.validator != nil && !p.validator(match) {
				continue
			}

			matches = append(matches, TLSDLPMatch{
				PatternID:   p.id,
				PatternName: p.name,
				Description: p.description,
				Level:       p.level,
				Score:       p.score,
				MitreATTCK:  p.mitre,
				Redacted:    tlsRedactMatch(match),
			})

			break // one match per pattern per scan
		}

		if len(matches) >= 5 {
			break
		}
	}

	if len(matches) > 0 {
		m.statsMu.Lock()
		m.stats.matchesFound += int64(len(matches))
		m.statsMu.Unlock()
	}

	return matches
}

// Stats returns DLP matcher statistics.
func (m *TLSDLPMatcher) Stats() (scans, matches int64) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	return m.stats.scansPerformed, m.stats.matchesFound
}

// tlsLuhnCheck validates a number string using the Luhn algorithm.
func tlsLuhnCheck(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// tlsValidateSSN checks if a matched SSN is valid.
func tlsValidateSSN(s string) bool {
	if len(s) != 11 {
		return false
	}
	area := s[:3]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if s[4:6] == "00" {
		return false
	}
	return s[7:] != "0000"
}

// tlsRedactMatch redacts the middle of a sensitive value for safe logging.
func tlsRedactMatch(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
