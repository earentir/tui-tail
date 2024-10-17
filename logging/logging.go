package logging

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var loggingEnabled = false

// Initialize application logging with the specified log file path
func InitAppLogging(logFilePath string) error {
	// Check if logFilePath is empty
	if logFilePath == "" {
		return nil // No logging to set up
	}

	// Determine absolute path
	absPath, err := filepath.Abs(logFilePath)
	if err != nil {
		return fmt.Errorf("Error getting absolute path of '%s': %v", logFilePath, err)
	}

	isDir := false

	// Check if the path exists
	fi, err := os.Stat(absPath)
	if err == nil {
		// Path exists
		if fi.IsDir() {
			isDir = true
		}
	} else if os.IsNotExist(err) {
		// Path does not exist
		// If the path ends with a path separator, treat it as a directory
		if strings.HasSuffix(absPath, string(os.PathSeparator)) {
			isDir = true
			// Create the directory
			err = os.MkdirAll(absPath, 0755)
			if err != nil {
				return fmt.Errorf("Error creating log directory '%s': %v", absPath, err)
			}
		} else {
			// Assume it's a file path, ensure parent directory exists
			dir := filepath.Dir(absPath)
			err = os.MkdirAll(dir, 0755)
			if err != nil {
				return fmt.Errorf("Error creating log directory '%s': %v", dir, err)
			}
		}
	} else {
		// Some other error accessing the path
		return fmt.Errorf("Error accessing log file path '%s': %v", absPath, err)
	}

	if isDir {
		// Append 'ttail.log' to the directory path
		absPath = filepath.Join(absPath, "ttail.log")
	}

	// Try to open or create the log file
	logFile, err := os.OpenFile(absPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Error opening log file '%s': %v", absPath, err)
	}

	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	loggingEnabled = true
	return nil
}

// LogAppAction logs application actions if logging is enabled
func LogAppAction(action string) {
	if loggingEnabled {
		log.Printf("Action: %s", action)
	}
}
