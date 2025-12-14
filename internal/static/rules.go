package static

import "regexp"

// Rule defines a security scanning rule
type Rule struct {
	Name        string
	Description string
	Severity    string
	Pattern     *regexp.Regexp
}

// Finding represents a detected security issue
type Finding struct {
	RuleName    string
	FilePath    string
	LineNumber  int
	MatchedText string
	Severity    string
}

// GetCredentialRules returns Rule A - Credential detection rules
func GetCredentialRules() []Rule {
	return []Rule{
		{
			Name:        "OpenAI API Key",
			Description: "Detected OpenAI API key (sk-proj-...)",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`sk-proj-[a-zA-Z0-9_-]{20,}`),
		},
		{
			Name:        "OpenAI Legacy Key",
			Description: "Detected legacy OpenAI API key (sk-...)",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`),
		},
		{
			Name:        "AWS Access Key ID",
			Description: "Detected AWS Access Key ID",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		},
		{
			Name:        "AWS Secret Access Key",
			Description: "Detected potential AWS Secret Access Key",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?`),
		},
		{
			Name:        "Generic API Key Assignment",
			Description: "Detected hardcoded API key assignment",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'][a-zA-Z0-9_\-]{16,}["']`),
		},
		{
			Name:        "Generic Secret Assignment",
			Description: "Detected hardcoded secret assignment",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}["']`),
		},
		{
			Name:        "GitHub Personal Access Token",
			Description: "Detected GitHub Personal Access Token",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		},
		{
			Name:        "Anthropic API Key",
			Description: "Detected Anthropic API key",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{20,}`),
		},
		{
			Name:        "Google API Key",
			Description: "Detected Google API key",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		},
		{
			Name:        "Private Key Header",
			Description: "Detected private key file content",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		},
	}
}
