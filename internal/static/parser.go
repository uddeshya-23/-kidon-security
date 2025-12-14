package static

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Package represents a parsed dependency
type Package struct {
	Name      string
	Version   string
	Ecosystem string // "PyPI", "Go", "npm"
	FilePath  string
}

// ParseDependencies walks a directory and parses lockfiles
func ParseDependencies(path string) ([]Package, error) {
	var packages []Package

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.IsDir() {
			return nil
		}

		switch info.Name() {
		case "requirements.txt":
			pkgs := parsePython(filePath)
			packages = append(packages, pkgs...)
		case "go.mod":
			pkgs := parseGoMod(filePath)
			packages = append(packages, pkgs...)
		case "package.json":
			pkgs := parsePackageJSON(filePath)
			packages = append(packages, pkgs...)
		}
		return nil
	})

	return packages, err
}

// parsePython parses requirements.txt
func parsePython(path string) []Package {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(file)

	// Regex for "flask==2.0.1" or "flask>=2.0"
	reExact := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)==([0-9\.]+)`)
	reRange := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)[><=]+([0-9\.]+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try exact match first
		matches := reExact.FindStringSubmatch(line)
		if len(matches) == 3 {
			pkgs = append(pkgs, Package{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "PyPI",
				FilePath:  path,
			})
			continue
		}

		// Try range match
		matches = reRange.FindStringSubmatch(line)
		if len(matches) == 3 {
			pkgs = append(pkgs, Package{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "PyPI",
				FilePath:  path,
			})
		}
	}
	return pkgs
}

// parseGoMod parses go.mod
func parseGoMod(path string) []Package {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(file)

	// Regex for "require github.com/foo/bar v1.2.3"
	re := regexp.MustCompile(`^\s*([a-zA-Z0-9\.\-_/]+)\s+v([0-9\.]+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			pkgs = append(pkgs, Package{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "Go",
				FilePath:  path,
			})
		}
	}
	return pkgs
}

// parsePackageJSON parses package.json dependencies
func parsePackageJSON(path string) []Package {
	// Simplified - just detect presence for now
	// Full JSON parsing would be more robust
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkgs []Package
	re := regexp.MustCompile(`"([a-zA-Z0-9\-_@/]+)":\s*"[\^~]?([0-9\.]+)"`)

	matches := re.FindAllStringSubmatch(string(content), -1)
	for _, match := range matches {
		if len(match) == 3 {
			pkgs = append(pkgs, Package{
				Name:      match[1],
				Version:   match[2],
				Ecosystem: "npm",
				FilePath:  path,
			})
		}
	}
	return pkgs
}
