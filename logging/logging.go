package logging

import (
	"log"
	"os"
	"path/filepath"
)

// Initialize application logging
func InitAppLogging() {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting executable path: %v", err)
	}
	appLogPath := filepath.Join(filepath.Dir(execPath), "ttail.log")

	logFile, err := os.OpenFile(appLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

// Log application actions
func LogAppAction(action string) {
	log.Printf("Action: %s", action)
}
