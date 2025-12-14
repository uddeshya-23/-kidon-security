//go:build !linux

package runtime

import "fmt"

// StartGuard is a stub for non-Linux platforms
// eBPF requires Linux kernel - run inside Docker container
func StartGuard() {
	fmt.Println("⚠️  ERROR: Guard mode requires Linux kernel with eBPF support.")
	fmt.Println("Run inside the Docker container:")
	fmt.Println("  docker build -f deploy/Dockerfile.kidon -t kidon-security .")
	fmt.Println("  docker run --privileged --pid=host kidon-security")
}
