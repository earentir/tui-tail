package main

import (
	"fmt"
	"log"
	"os"

	"ttail/app"
	"ttail/config"
	"ttail/logging"

	"github.com/spf13/cobra"
)

var appVersion = "0.3.47"

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
		initialLines int
		maxLines     int
		rulesFile    string
		configFile   string
		fullMode     bool
		headMode     bool
		logFile      string
		follow       bool
		followName   bool
		retry        bool
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

	rootCmd.Flags().IntVarP(&initialLines, "num-lines", "n", cfg.NumLines, "Number of initial lines to load")
	rootCmd.Flags().IntVar(&maxLines, "max-lines", cfg.MaxLines, "Maximum number of lines to keep in memory")
	rootCmd.Flags().StringVar(&rulesFile, "rules-file", cfg.RulesFile, "JSON file containing matching rules to load at startup")
	rootCmd.Flags().StringVar(&configFile, "colour-file", cfg.ColourFile, "JSON configuration file for color rules and settings")
	rootCmd.Flags().BoolVar(&fullMode, "full", cfg.Full, "Load and navigate the full file without loading all lines into memory")
	rootCmd.Flags().BoolVar(&headMode, "head", cfg.Head, "Show the first N lines of the file instead of the last N lines")
	rootCmd.Flags().StringVar(&logFile, "log-file", cfg.LogFile, "Log file path or directory to write application logs to")
	rootCmd.Flags().BoolVarP(&follow, "follow", "f", cfg.Follow, "Follow (tail) the file and show new lines as they are written")
	rootCmd.Flags().BoolVarP(&followName, "follow-name", "F", cfg.FollowName, "Follow by name: reopen when the file is replaced (e.g. log rotate), like GNU tail -F")
	rootCmd.Flags().BoolVar(&retry, "retry", cfg.Retry, "Keep trying to open the file when it is unavailable (e.g. not yet created)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Fatalf("Error running application: %v", err)
	}
}
