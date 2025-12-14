//go:build !linux

package runtime

import "fmt"

// GuardMode specifies which protection to enable
type GuardMode int

const (
	GuardModeProcess GuardMode = 1 << iota
	GuardModeNetwork
	GuardModeAll = GuardModeProcess | GuardModeNetwork
)

// StartGuard is a stub for non-Linux platforms
func StartGuard() {
	printDockerInstructions()
}

// StartNetworkGuard is a stub for non-Linux platforms
func StartNetworkGuard(cgroupPath string) {
	printDockerInstructions()
}

// StartFullGuard is a stub for non-Linux platforms
func StartFullGuard(cgroupPath string) {
	printDockerInstructions()
}

// StartGuardWithMode is a stub for non-Linux platforms
func StartGuardWithMode(mode GuardMode) {
	printDockerInstructions()
}

func printDockerInstructions() {
	fmt.Println("⚠️  ERROR: Guard mode requires Linux kernel with eBPF support.")
	fmt.Println("")
	fmt.Println("Run inside the Docker container:")
	fmt.Println("  docker build -f deploy/Dockerfile.kidon -t kidon-security .")
	fmt.Println("  docker run --privileged --pid=host kidon-security guard")
	fmt.Println("")
	fmt.Println("For network guard (v0.2.0):")
	fmt.Println("  docker run --privileged --pid=host --cgroupns=host kidon-security guard --network")
}
