package offensive

// Result represents the outcome of a single attack attempt
type Result struct {
	Type     string // e.g., "ASI-01 Goal Hijacking"
	Prompt   string // What we sent
	Response string // What the agent replied
	Success  bool   // Did we break the agent?
	Severity string // CRITICAL, HIGH, MEDIUM
}

// Attacker defines the interface for different attack strategies
type Attacker interface {
	Name() string
	Run(targetURL string) ([]Result, error)
}
