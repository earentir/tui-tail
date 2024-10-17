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
	cliApp.Version("v version", "ttail 0.2.43")
	cliApp.LongDesc = "A terminal-based application for viewing and filtering log files using matching rules"

	inputMessagesFile := cliApp.StringArg("FILE", "", "The log file to view")

	initialLines := cliApp.IntOpt("n num-lines", app.DefaultInitialLines, "Number of initial lines to load")
	maxLines := cliApp.IntOpt("max-lines", app.DefaultMaxLines, "Maximum number of lines to keep in memory")
	rulesFile := cliApp.StringOpt("r rules-file", "", "JSON file containing matching rules to load at startup")
	configFile := cliApp.StringOpt("c colour-file", "", "JSON configuration file for color rules and settings")
	fullMode := cliApp.BoolOpt("full", false, "Load and navigate the full file without loading all lines into memory")

	// Add the --head flag
	headMode := cliApp.BoolOpt("head", false, "Show the first N lines of the file instead of the last N lines")

	cliApp.Action = func() {
		logging.InitAppLogging()
		logging.LogAppAction(app.MsgAppStarted)
		defer logging.LogAppAction(app.MsgAppStopped)

		appInstance := app.NewApp(
			*inputMessagesFile,
			*initialLines,
			*maxLines,
			*rulesFile,
			*configFile,
			*fullMode,
			*headMode,
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
