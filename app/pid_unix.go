//go:build !windows

package app

import "syscall"

// processExists reports whether the process with the given PID exists (Unix: kill(pid, 0)).
func processExists(pid int) bool {
	return syscall.Kill(pid, syscall.Signal(0)) == nil
}
