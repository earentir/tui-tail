package main

import (
	"fmt"
	"log"
	"os"

	"ttail/app"
	"ttail/logging"

	cli "github.com/jawher/mow.cli"
)

func main() {
	cliApp := cli.App("ttail", "A terminal-based application for viewing and filtering log files using matching rules")
	cliApp.Version("v version", "ttail 0.2.47")
	cliApp.LongDesc = "A terminal-based application for viewing and filtering log files using matching rules"

	cliApp.Spec = "FILE [-n --num-lines] [--max-lines] [--rules-file] [--colour-file] [--full] [--head] [--log-file]"

	inputMessagesFile := cliApp.StringArg("FILE", "", "The log file to view")

	initialLines := cliApp.IntOpt("n num-lines", app.DefaultInitialLines, "Number of initial lines to load")
	maxLines := cliApp.IntOpt("max-lines", app.DefaultMaxLines, "Maximum number of lines to keep in memory")
	rulesFile := cliApp.StringOpt("rules-file", "", "JSON file containing matching rules to load at startup")
	configFile := cliApp.StringOpt("colour-file", "", "JSON configuration file for color rules and settings")
	fullMode := cliApp.BoolOpt("full", false, "Load and navigate the full file without loading all lines into memory")
	headMode := cliApp.BoolOpt("head", false, "Show the first N lines of the file instead of the last N lines")
	logFile := cliApp.StringOpt("log-file", "", "Log file path or directory to write application logs to")

	cliApp.Action = func() {
		// Initialize logging if logFile is provided
		if *logFile != "" {
			err := logging.InitAppLogging(*logFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing logging: %v\n", err)
			} else {
				logging.LogAppAction(app.MsgAppStarted)
				defer logging.LogAppAction(app.MsgAppStopped)
			}
		}

		appInstance := app.NewApp(
			*inputMessagesFile,
			*initialLines,
			*maxLines,
			*rulesFile,
			*configFile,
			*fullMode,
			*headMode,
			*logFile, // Only if needed in App
		)

		if err := appInstance.Run(); err != nil {
			logging.LogAppAction(fmt.Sprintf("Error running application: %v", err))
			log.Fatalf("Error running application: %v", err)
		}
	}

	if err := cliApp.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
