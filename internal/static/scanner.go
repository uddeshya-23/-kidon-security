package static

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Scanner performs static security analysis
type Scanner struct {
	Rules       []Rule
	SkipDirs    []string
	SkipExts    []string
	MaxFileSize int64
}

// NewScanner creates a new scanner with default credential rules
func NewScanner() *Scanner {
	return &Scanner{
		Rules: GetCredentialRules(),
		SkipDirs: []string{
			".git",
			"node_modules",
			"vendor",
			"__pycache__",
			".venv",
			"venv",
			"dist",
			"build",
			".idea",
			".vscode",
		},
		SkipExts: []string{
			".exe", ".dll", ".so", ".dylib",
			".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
			".pdf", ".doc", ".docx",
			".zip", ".tar", ".gz", ".rar",
			".mp3", ".mp4", ".wav", ".avi",
			".woff", ".woff2", ".ttf", ".eot",
			".pyc", ".pyo",
			".o", ".a",
		},
		MaxFileSize: 10 * 1024 * 1024, // 10MB max
	}
}

// ScanDirectory recursively scans a directory for security issues
func (s *Scanner) ScanDirectory(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip directories
		if info.IsDir() {
			if s.shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip by extension
		ext := strings.ToLower(filepath.Ext(path))
		if s.shouldSkipExt(ext) {
			return nil
		}

		// Skip large files
		if info.Size() > s.MaxFileSize {
			return nil
		}

		// Scan the file
		fileFindings, err := s.ScanFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}
		findings = append(findings, fileFindings...)

		return nil
	})

	return findings, err
}

// ScanFile scans a single file for security issues
func (s *Scanner) ScanFile(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Increase buffer size for long lines
	const maxCapacity = 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range s.Rules {
			if match := rule.Pattern.FindString(line); match != "" {
				// Truncate match for display
				displayMatch := match
				if len(displayMatch) > 60 {
					displayMatch = displayMatch[:57] + "..."
				}

				findings = append(findings, Finding{
					RuleName:    rule.Name,
					FilePath:    path,
					LineNumber:  lineNum,
					MatchedText: displayMatch,
					Severity:    rule.Severity,
				})
			}
		}
	}

	return findings, scanner.Err()
}

func (s *Scanner) shouldSkipDir(name string) bool {
	for _, skip := range s.SkipDirs {
		if name == skip {
			return true
		}
	}
	return false
}

func (s *Scanner) shouldSkipExt(ext string) bool {
	for _, skip := range s.SkipExts {
		if ext == skip {
			return true
		}
	}
	return false
}
