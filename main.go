package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"ttail/app"
	"ttail/config"
	"ttail/logging"

	"github.com/spf13/cobra"
)

var appVersion = "0.3.57"

// parseNumLines parses -n like GNU tail: "N" = last N lines, "+N" = from line N to end.
// Returns (initialLines, linesFrom). Exactly one of linesFrom > 0 or initialLines used.
func parseNumLines(s string) (initialLines, linesFrom int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("invalid number of lines: %q", s)
	}
	if strings.HasPrefix(s, "+") {
		n, err := strconv.Atoi(strings.TrimPrefix(s, "+"))
		if err != nil || n < 1 {
			return 0, 0, fmt.Errorf("invalid number of lines: %q (use +N with N >= 1)", s)
		}
		return 0, n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, 0, fmt.Errorf("invalid number of lines: %q (use N with N >= 0)", s)
	}
	return n, 0, nil
}

func main() {
	cfg, created, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if created {
		path, _ := config.Path()
		fmt.Fprintf(os.Stderr, "Default config generated in %s\n", path)
	}

	var (
		numLinesStr  string
		maxLines     int
		rulesFile    string
		configFile   string
		fullMode     bool
		headMode     bool
		logFile      string
		follow       bool
		followName   bool
		retry        bool
		bytes        string
	)

	rootCmd := &cobra.Command{
		Use:   "ttail [FILE]",
		Short: "A tui for viewing files",
		Long:  "A tui for viewing and filtering files using matching rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputMessagesFile := args[0]
			if followName && !follow {
				follow = true // -F implies -f (GNU tail behaviour)
			}

			// Parse -n like GNU tail: N = last N lines, +N = from line N to end
			initialLines, linesFrom, err := parseNumLines(numLinesStr)
			if err != nil {
				return err
			}

			// Initialize logging if logFile is provided
			if logFile != "" {
				err := logging.InitAppLogging(logFile)
				if err != nil {
					return fmt.Errorf("initializing logging: %w", err)
				}
				logging.LogAppAction(app.MsgAppStarted)
				defer logging.LogAppAction(app.MsgAppStopped)
			}

			appInstance := app.NewApp(
				inputMessagesFile,
				initialLines,
				maxLines,
				rulesFile,
				configFile,
				fullMode,
				headMode,
				logFile,
				follow,
				followName,
				retry,
				bytes,
				linesFrom,
			)

			if err := appInstance.Run(); err != nil {
				logging.LogAppAction(fmt.Sprintf("Error running application: %v", err))
				return err
			}
			return nil
		},
	}

	rootCmd.Version = appVersion
	rootCmd.SetVersionTemplate("ttail {{.Version}}\n")

	rootCmd.Flags().StringVarP(&numLinesStr, "num-lines", "n", strconv.Itoa(cfg.NumLines), "Lines: N = last N lines, +N = from line N to end (same as GNU tail -n)")
	rootCmd.Flags().IntVar(&maxLines, "max-lines", cfg.MaxLines, "Maximum number of lines to keep in memory")
	rootCmd.Flags().StringVarP(&bytes, "bytes", "c", "", "Bytes: N = last N bytes, +N = from byte N to end (GNU tail -c)")
	rootCmd.Flags().StringVar(&rulesFile, "rules-file", cfg.RulesFile, "JSON file containing matching rules to load at startup")
	rootCmd.Flags().StringVar(&configFile, "colour-file", cfg.ColourFile, "JSON configuration file for color rules and settings")
	rootCmd.Flags().BoolVar(&fullMode, "full", false, "Load and navigate the full file without loading all lines into memory")
	rootCmd.Flags().BoolVar(&headMode, "head", false, "Show the first N lines of the file instead of the last N lines")
	rootCmd.Flags().StringVar(&logFile, "log-file", cfg.LogFile, "Log file path or directory to write application logs to")
	rootCmd.Flags().BoolVarP(&follow, "follow", "f", cfg.Follow, "Follow (tail) the file and show new lines as they are written")
	rootCmd.Flags().BoolVarP(&followName, "follow-name", "F", cfg.FollowName, "Follow by name: reopen when the file is replaced (e.g. log rotate), like GNU tail -F")
	rootCmd.Flags().BoolVar(&retry, "retry", false, "Keep trying to open the file when it is unavailable (e.g. not yet created)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Fatalf("Error running application: %v", err)
	}
}
