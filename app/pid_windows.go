//go:build windows

package app

import "golang.org/x/sys/windows"

// processExists reports whether a process with the given PID is running (OpenProcess probe).
func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}
