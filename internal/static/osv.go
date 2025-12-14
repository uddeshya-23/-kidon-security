package static

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OSVQuery represents a single package query
type OSVQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

// OSVPackage represents package identification
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVVuln represents a vulnerability
type OSVVuln struct {
	Id       string `json:"id"`
	Summary  string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// OSVResponse represents response for a single query
type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

// OSVBatchResponse represents the batch API response
type OSVBatchResponse struct {
	Results []OSVResponse `json:"results"`
}

// CheckVulnerabilities queries OSV.dev for known vulnerabilities
func CheckVulnerabilities(pkgs []Package) []Finding {
	if len(pkgs) == 0 {
		return nil
	}

	// Build batch query
	var queries []OSVQuery
	for _, p := range pkgs {
		queries = append(queries, OSVQuery{
			Package: OSVPackage{Name: p.Name, Ecosystem: p.Ecosystem},
			Version: p.Version,
		})
	}

	payload := map[string]interface{}{"queries": queries}
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("⚠️ JSON Error:", err)
		return nil
	}

	// Call OSV API
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Println("⚠️ OSV API Error:", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("⚠️ OSV API returned status: %d\n", resp.StatusCode)
		return nil
	}

	var results OSVBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		fmt.Println("⚠️ OSV Response Parse Error:", err)
		return nil
	}

	// Convert to Findings
	var findings []Finding
	for i, res := range results.Results {
		if len(res.Vulns) > 0 && i < len(pkgs) {
			pkg := pkgs[i]
			for _, vuln := range res.Vulns {
				summary := vuln.Summary
				if len(summary) > 100 {
					summary = summary[:100] + "..."
				}

				findings = append(findings, Finding{
					Severity:    "CRITICAL",
					RuleName:    "Supply Chain: " + vuln.Id,
					MatchedText: fmt.Sprintf("%s@%s - %s", pkg.Name, pkg.Version, summary),
					FilePath:    pkg.FilePath,
					LineNumber:  0,
				})
			}
		}
	}

	return findings
}
