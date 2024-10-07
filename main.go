// main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/hpcloud/tail"
	cli "github.com/jawher/mow.cli"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

// Constants for messages and settings
const (
	DefaultInitialLines = 10
	DefaultMaxLines     = 1000
	MsgAppStarted       = "Application started"
	MsgAppStopped       = "Application stopped"
	ErrFileOpen         = "Error opening file: %v"
	ErrFileRead         = "Error reading file: %v"
	ErrFileCreate       = "Error creating file: %v"
	ErrFileWrite        = "Error writing to file: %v"
	MsgFileSaved        = "File saved successfully: %s"
	MsgInvalidInput     = "Invalid input"
	MsgRuleEmpty        = "Rule cannot be empty"
	MsgFilenameEmpty    = "Filename cannot be empty"
	MsgInvalidContext   = "Cannot save in current context"
)

// Key bindings
var keyBindings = map[string]rune{
	"quit":   'q',
	"save":   's',
	"view":   'v',
	"delete": 'd',
	"help":   'h',
}

// FocusState represents the current focus in the UI
type FocusState int

const (
	FocusMessages FocusState = iota
	FocusRuleInput
	FocusRulesView
	FocusSaveInput
	FocusViewModal
)

// app represents the application state
type app struct {
	tviewApp          *tview.Application
	messagesView      *tview.List
	rulesView         *tview.TextView
	ruleInput         *tview.InputField
	viewModal         *tview.TextView
	saveFilenameInput *tview.InputField
	progressBar       *tview.TextView
	helpText          *tview.TextView // Existing help pane
	flex              *tview.Flex
	rules             []rule
	colorRules        []colorRule
	lines             []string
	linesMutex        sync.Mutex
	selectedLineIndex int
	selectedRuleIndex int
	currentFocus      FocusState
	inputMessagesFile string
	initialLines      int
	maxLines          int
	rulesFile         string
	configFile        string
	fullMode          bool // Indicates if --full flag is set
	fileOffset        int64
	fileMutex         sync.Mutex
	cancelFunc        context.CancelFunc
}

// rule represents a matching rule
type rule struct {
	Text          string         `json:"text"`
	CaseSensitive bool           `json:"caseSensitive"`
	PartialMatch  bool           `json:"partialMatch"`
	Regex         *regexp.Regexp `json:"-"`
	RegexString   string         `json:"regex"` // For JSON marshalling/unmarshalling
}

// colorRule represents a color formatting rule
type colorRule struct {
	Pattern string         `json:"pattern"`
	Regex   *regexp.Regexp `json:"-"`
	Color   string         `json:"color"`
	Label   string         `json:"label"`
	RuleID  string         `json:"rule_id"`
}

func main() {
	cliApp := cli.App("ttail", "A terminal-based application for viewing and filtering log files using matching rules")
	cliApp.Version("v version", "ttail 0.1.0")
	cliApp.LongDesc = "A terminal-based application for viewing and filtering log files using matching rules"

	inputMessagesFile := cliApp.StringArg("FILE", "", "The log file to view")

	initialLines := cliApp.IntOpt("n num-lines", DefaultInitialLines, "Number of initial lines to load")
	maxLines := cliApp.IntOpt("max-lines", DefaultMaxLines, "Maximum number of lines to keep in memory")
	rulesFile := cliApp.StringOpt("r rules-file", "", "JSON file containing matching rules to load at startup")
	configFile := cliApp.StringOpt("c config-file", "", "JSON configuration file for color rules and settings")
	fullMode := cliApp.BoolOpt("full", false, "Load and navigate the full file without loading all lines into memory")

	cliApp.Action = func() {
		initAppLogging()
		logAppAction(MsgAppStarted)
		defer logAppAction(MsgAppStopped)
		appInstance := newApp(*inputMessagesFile)
		appInstance.initialLines = *initialLines
		appInstance.maxLines = *maxLines
		appInstance.rulesFile = *rulesFile
		appInstance.configFile = *configFile
		appInstance.fullMode = *fullMode

		if err := appInstance.Run(); err != nil {
			logAppAction(fmt.Sprintf("Error running application: %v", err))
			log.Fatalf("Error running application: %v", err)
		}
	}

	if err := cliApp.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Initialize application logging
func initAppLogging() {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting executable path: %v", err)
	}
	appLogPath := filepath.Join(filepath.Dir(execPath), "gtt.log")

	logFile, err := os.OpenFile(appLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

// Log application actions
func logAppAction(action string) {
	log.Printf("Action: %s", action)
}

// Create a new application instance
func newApp(inputMessagesFile string) *app {
	appInstance := &app{
		tviewApp:          tview.NewApplication(),
		inputMessagesFile: inputMessagesFile,
		rules:             []rule{},
		colorRules:        []colorRule{},
		currentFocus:      FocusMessages,
	}
	appInstance.initUI()
	appInstance.loadConfig()
	appInstance.loadRules()
	logAppAction("New app instance created")
	return appInstance
}

// Run starts the application
func (app *app) Run() error {
	logAppAction("Application run started")
	ctx, cancel := context.WithCancel(context.Background())
	app.cancelFunc = cancel
	app.setupHandlers()

	if app.fullMode {
		return app.runFullMode(ctx)
	} else {
		app.displayInitialInputMessages()
		go app.tailInputMessagesFile(ctx)
		return app.tviewApp.Run()
	}
}

// runFullMode handles the --full flag functionality
func (app *app) runFullMode(ctx context.Context) error {
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logAppAction(fmt.Sprintf(ErrFileOpen, err))
		app.messagesView.AddItem(fmt.Sprintf(ErrFileOpen, err), "", 0, nil)
		return err
	}
	defer file.Close()

	app.fileMutex.Lock()
	app.fileOffset = 0
	app.fileMutex.Unlock()

	app.loadFullModeInitialLines(file)

	go app.monitorFullModeFile(ctx, file)

	return app.tviewApp.Run()
}

// loadFullModeInitialLines loads the initial set of lines in full mode
func (app *app) loadFullModeInitialLines(file *os.File) {
	reader := bufio.NewReader(file)
	for i := 0; i < app.initialLines; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logAppAction(fmt.Sprintf(ErrFileRead, err))
				app.messagesView.AddItem(fmt.Sprintf(ErrFileRead, err), "", 0, nil)
			}
			break
		}
		line = strings.TrimRight(line, "\n")
		app.messagesView.AddItem(app.applyColorRules(line), "", 0, nil)
		app.fileMutex.Lock()
		app.fileOffset += int64(len(line)) + 1 // +1 for newline
		app.fileMutex.Unlock()
	}

	// Update progress bar and help pane after initial load
	app.updateProgressBar()
	app.updateHelpPane()
}

// monitorFullModeFile monitors the file for new lines in full mode
func (app *app) monitorFullModeFile(ctx context.Context, file *os.File) {
	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			logAppAction("Full mode goroutine exiting")
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					logAppAction(fmt.Sprintf("Error reading line: %v", err))
					app.showMessage(fmt.Sprintf("Error reading line: %v", err), app.flex)
				}
				// Wait before retrying
				continue
			}
			line = strings.TrimRight(line, "\n")
			app.messagesView.AddItem(app.applyColorRules(line), "", 0, nil)
			app.updateProgressBar()
			app.updateHelpPane()
			app.fileMutex.Lock()
			app.fileOffset += int64(len(line)) + 1
			app.fileMutex.Unlock()
		}
	}
}

// loadConfig loads color rules from the config file or initializes default rules
func (app *app) loadConfig() {
	if app.configFile != "" {
		err := app.loadConfigFromFile(app.configFile)
		if err != nil {
			logAppAction(fmt.Sprintf("Error loading config file: %v", err))
		}
	} else {
		app.initDefaultColorRules()
	}
}

// loadRules loads matching rules from the rules file
func (app *app) loadRules() {
	if app.rulesFile != "" {
		err := app.loadRulesFromFile(app.rulesFile)
		if err != nil {
			logAppAction(fmt.Sprintf("Error loading rules file: %v", err))
		}
	}
}

// initDefaultColorRules initializes default color rules
func (app *app) initDefaultColorRules() {
	// Initialize default color rules
	messagesPattern := `([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+\[\d+\])`
	app.colorRules = []colorRule{
		{
			Pattern: messagesPattern,
			Color:   "[green]",
			Label:   "Messages",
			RuleID:  "messages-matcher",
		},
	}
	app.compileColorRules()
}

// compileColorRules compiles the regex patterns for color rules
func (app *app) compileColorRules() {
	for i, cr := range app.colorRules {
		regex, err := regexp.Compile(cr.Pattern)
		if err != nil {
			logAppAction(fmt.Sprintf("Error compiling color rule regex: %v", err))
			continue
		}
		app.colorRules[i].Regex = regex
	}
}

// loadConfigFromFile loads color rules from a JSON config file
func (app *app) loadConfigFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Error opening config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var config struct {
		ColorRules []colorRule `json:"color_rules"`
	}
	err = decoder.Decode(&config)
	if err != nil {
		return fmt.Errorf("Error decoding config file: %v", err)
	}

	app.colorRules = config.ColorRules
	app.compileColorRules()
	return nil
}

// loadRulesFromFile loads matching rules from a JSON rules file
func (app *app) loadRulesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Error opening rules file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var rules []rule
	err = decoder.Decode(&rules)
	if err != nil {
		return fmt.Errorf("Error decoding rules file: %v", err)
	}

	// Compile regex patterns
	for i := range rules {
		if rules[i].RegexString != "" {
			pattern := rules[i].RegexString
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("Invalid regex in rules file: %v", err)
			}
			rules[i].Regex = regex
		}
	}

	app.rules = rules
	return nil
}

// displayInitialInputMessages loads the initial set of lines in normal mode
func (app *app) displayInitialInputMessages() {
	logAppAction("Displaying initial input messages")
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logAppAction(fmt.Sprintf(ErrFileOpen, err))
		app.messagesView.AddItem(fmt.Sprintf(ErrFileOpen, err), "", 0, nil)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for i := 0; i < app.initialLines; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logAppAction(fmt.Sprintf(ErrFileRead, err))
				app.messagesView.AddItem(fmt.Sprintf(ErrFileRead, err), "", 0, nil)
			}
			break
		}
		line = strings.TrimRight(line, "\n")
		app.addLine(line)
		app.messagesView.AddItem(app.applyColorRules(line), "", 0, nil)
		app.fileMutex.Lock()
		app.fileOffset += int64(len(line)) + 1 // +1 for newline
		app.fileMutex.Unlock()
	}

	// Update progress bar and help pane after initial load
	app.updateProgressBar()
	app.updateHelpPane()
}

// setupHandlers sets up input handlers and event listeners
func (app *app) setupHandlers() {
	app.ruleInput.SetDoneFunc(app.handleRuleInput)
	app.tviewApp.SetInputCapture(app.handleGlobalInput)

	// Handle selection change in messagesView
	app.messagesView.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		app.selectedLineIndex = index
		app.updateProgressBar() // Update progress bar on selection change
		app.updateHelpPane()    // Update help pane on selection change
	})

	// Handle selection in messagesView (on Enter key)
	app.messagesView.SetSelectedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		app.selectedLineIndex = index
		app.viewSelectedLine()
	})
}

// handleRuleInput handles adding new matching rules
func (app *app) handleRuleInput(key tcell.Key) {
	if key == tcell.KeyEnter {
		ruleText := app.ruleInput.GetText()
		if ruleText != "" {
			rule, err := parseRule(ruleText)
			if err != nil {
				app.showMessage(fmt.Sprintf("Error parsing rule: %v", err), app.flex)
				return
			}
			app.rules = append(app.rules, rule)
			app.updateRulesView()
			app.ruleInput.SetText("")
		}
	}
}

// handleGlobalInput handles global key shortcuts
func (app *app) handleGlobalInput(event *tcell.EventKey) *tcell.EventKey {
	// Handle global shortcuts
	switch event.Key() {
	case tcell.KeyTab:
		app.cycleFocus()
		return nil
	case tcell.KeyEscape:
		if app.tviewApp.GetFocus() == app.viewModal {
			app.closeViewModal()
			return nil
		} else if app.tviewApp.GetFocus() == app.saveFilenameInput {
			app.cancelSave()
			return nil
		}
	case tcell.KeyRune:
		switch event.Rune() {
		case keyBindings["help"]:
			app.showHelp()
			return nil
		case keyBindings["quit"]:
			if app.tviewApp.GetFocus() != app.ruleInput && app.tviewApp.GetFocus() != app.saveFilenameInput {
				app.quit()
				return nil
			}
		}
	}

	// Handle pane-specific shortcuts
	currentFocus := app.currentFocus
	switch currentFocus {
	case FocusMessages:
		switch event.Key() {
		case tcell.KeyEnter:
			app.viewSelectedLine()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case keyBindings["view"]:
				app.viewSelectedLine()
			case keyBindings["save"]:
				app.initiateSave()
			case keyBindings["delete"]:
				app.deleteSelected()
			}
			return nil
		}
	case FocusRulesView:
		// Implement similar handling if using selectable rulesView
	case FocusViewModal:
		switch event.Key() {
		case tcell.KeyRune:
			switch event.Rune() {
			case keyBindings["view"]:
				app.closeViewModal()
				return nil
			case keyBindings["save"]:
				app.initiateSave()
				return nil
			}
		}
	}

	return event
}

// cycleFocus cycles the UI focus between different panes
func (app *app) cycleFocus() {
	focusOrder := []FocusState{FocusMessages, FocusRuleInput, FocusRulesView}
	oldFocus := app.currentFocus
	app.currentFocus = focusOrder[(int(app.currentFocus)+1)%len(focusOrder)]
	switch app.currentFocus {
	case FocusMessages:
		app.tviewApp.SetFocus(app.messagesView)
	case FocusRuleInput:
		app.tviewApp.SetFocus(app.ruleInput)
	case FocusRulesView:
		app.tviewApp.SetFocus(app.rulesView)
	}
	logAppAction(fmt.Sprintf("Focus cycled from %d to %d", oldFocus, app.currentFocus))
}

// viewSelectedLine displays the selected line in a modal
func (app *app) viewSelectedLine() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < app.messagesView.GetItemCount() {
		// Get the selected item's text
		mainText, _ := app.messagesView.GetItemText(app.selectedLineIndex)
		app.viewModal.Clear()
		app.viewModal.SetText(fmt.Sprintf("[white]%s[-]", mainText))
		app.tviewApp.SetRoot(app.viewModal, true)
		app.tviewApp.SetFocus(app.viewModal)
		app.currentFocus = FocusViewModal
		logAppAction(fmt.Sprintf("Viewed selected line: %d", app.selectedLineIndex))
	}
}

// closeViewModal closes the modal displaying a selected line
func (app *app) closeViewModal() {
	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

// initiateSave initiates the save operation by displaying the save input field
func (app *app) initiateSave() {
	logAppAction("Initiating save operation")
	app.saveFilenameInput.SetText("")
	app.saveFilenameInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			app.handleSaveInput()
		}
	})
	app.flex.AddItem(app.saveFilenameInput, 1, 0, true)
	app.tviewApp.SetFocus(app.saveFilenameInput)
	app.currentFocus = FocusSaveInput
}

// handleSaveInput handles the saving of log content to a file
func (app *app) handleSaveInput() {
	filename := app.saveFilenameInput.GetText()
	app.flex.RemoveItem(app.saveFilenameInput)
	if strings.TrimSpace(filename) == "" {
		logAppAction(MsgFilenameEmpty)
		app.showMessage(MsgFilenameEmpty, app.flex)
		return
	}

	var contentToSave []string
	var err error

	switch app.currentFocus {
	case FocusMessages:
		if app.fullMode {
			contentToSave, err = app.getFullContent()
			if err != nil {
				logAppAction(fmt.Sprintf("Error getting full content: %v", err))
				app.showMessage(fmt.Sprintf("Error getting full content: %v", err), app.flex)
				return
			}
		} else {
			app.linesMutex.Lock()
			contentToSave = append([]string{}, app.lines...)
			app.linesMutex.Unlock()
		}
	case FocusRulesView:
		contentToSave = rulesToStrings(app.rules)
	case FocusViewModal:
		contentToSave = []string{app.viewModal.GetText(true)}
	default:
		logAppAction(MsgInvalidContext)
		app.showMessage(MsgInvalidContext, app.flex)
		return
	}

	err = saveToFile(filename, contentToSave)
	if err != nil {
		logAppAction(fmt.Sprintf(ErrFileWrite, err))
		app.showMessage(fmt.Sprintf(ErrFileWrite, err), app.flex)
	} else {
		logAppAction(fmt.Sprintf(MsgFileSaved, filename))
		app.showMessage(fmt.Sprintf(MsgFileSaved, filename), app.flex)
	}
}

// cancelSave cancels the save operation and returns focus to the messages view
func (app *app) cancelSave() {
	app.flex.RemoveItem(app.saveFilenameInput)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

// deleteSelected deletes the selected line or rule
func (app *app) deleteSelected() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < app.messagesView.GetItemCount() {
		app.messagesView.RemoveItem(app.selectedLineIndex)
		if app.fullMode {
			// In full mode, we don't store lines in memory
			// Deletion can be a no-op or handled differently
			app.showMessage("Deletion not supported in full mode", app.flex)
		} else {
			app.linesMutex.Lock()
			defer app.linesMutex.Unlock()
			if app.selectedLineIndex < len(app.lines) {
				app.lines = append(app.lines[:app.selectedLineIndex], app.lines[app.selectedLineIndex+1:]...)
			}
		}
		app.updateProgressBar()
		app.updateHelpPane()
	} else if app.currentFocus == FocusRulesView && app.selectedRuleIndex < len(app.rules) {
		app.rules = append(app.rules[:app.selectedRuleIndex], app.rules[app.selectedRuleIndex+1:]...)
		if app.selectedRuleIndex >= len(app.rules) && len(app.rules) > 0 {
			app.selectedRuleIndex = len(app.rules) - 1
		}
		app.updateRulesView()
	}
}

// quit gracefully quits the application
func (app *app) quit() {
	app.cancelFunc()
	app.tviewApp.Stop()
}

// initUI initializes the UI components and layout
func (app *app) initUI() {
	// Initialize messagesView
	app.messagesView = tview.NewList()
	app.messagesView.ShowSecondaryText(false)
	app.messagesView.SetBorder(true)
	app.messagesView.SetTitle("Messages")

	// Initialize rulesView
	app.rulesView = tview.NewTextView()
	app.rulesView.SetDynamicColors(true)
	app.rulesView.SetBorder(true)
	app.rulesView.SetTitle("Matching Rules")

	// Initialize ruleInput
	app.ruleInput = tview.NewInputField()
	app.ruleInput.SetLabel("Add Matching Rule: ")
	app.ruleInput.SetFieldWidth(30)

	// Initialize viewModal
	app.viewModal = tview.NewTextView()
	app.viewModal.SetDynamicColors(true)
	app.viewModal.SetWordWrap(true)
	app.viewModal.SetBackgroundColor(tcell.ColorDarkGray)
	app.viewModal.SetBorder(true)
	app.viewModal.SetTitle("View Line - Press 'v', 'Enter', or 'Esc' to close")
	app.viewModal.SetTitleAlign(tview.AlignLeft)

	// Initialize saveFilenameInput
	app.saveFilenameInput = tview.NewInputField()
	app.saveFilenameInput.SetLabel("Save as: ")
	app.saveFilenameInput.SetFieldWidth(30)

	// Initialize progressBar
	app.progressBar = tview.NewTextView()
	app.progressBar.SetDynamicColors(true)
	app.progressBar.SetBorder(false)
	app.progressBar.SetTitle("") // No title for progress bar

	// Initialize helpText (Existing Bottom Help Pane)
	app.helpText = tview.NewTextView()
	app.helpText.SetDynamicColors(true)
	app.helpText.SetBorder(false)
	app.helpText.SetTextColor(tcell.ColorYellow)
	app.helpText.SetText("Press 'h' for help | Line: 0 / 0") // Initial status

	// Create a top FlexRow containing messagesView and rulesView side by side
	topFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(app.messagesView, 0, 8, false) // Adjust the ratio as needed

	// Initialize the main Flex layout with topFlex and other components stacked vertically
	app.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(topFlex, 0, 8, false).
		AddItem(app.ruleInput, 1, 0, false).
		AddItem(app.rulesView, 0, 2, false).         // Adjust the ratio as needed
		AddItem(app.saveFilenameInput, 0, 0, false). // Initially hidden
		AddItem(app.progressBar, 1, 0, false).
		AddItem(app.helpText, 1, 0, false) // Existing help pane

	// Set root and initial focus
	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

// showHelp displays the help modal with keybindings and flags
func (app *app) showHelp() {
	helpContent := `
Keybindings:
- Tab: Cycle focus
- Up/Down: Navigate
- Enter/v: View selected line
- s: Save
- d: Delete selected
- q: Quit
- h: Show this help

Command-line Flags:
- -n, --num-lines: Number of initial lines to load
- --max-lines: Maximum number of lines to keep in memory
- -r, --rules-file: JSON file containing matching rules to load at startup
- -c, --config-file: JSON configuration file for color rules and settings
- --full: Load and navigate the full file without loading all lines into memory
`
	app.showMessage(helpContent, app.flex)
}

// showMessage displays a modal with the given message
func (app *app) showMessage(message string, returnTo tview.Primitive) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			app.tviewApp.SetRoot(returnTo, true)
			app.tviewApp.SetFocus(returnTo)
		})
	app.tviewApp.SetRoot(modal, true)
}

// tailInputMessagesFile tails the input messages file in normal mode
func (app *app) tailInputMessagesFile(ctx context.Context) {
	logAppAction("Starting to tail input messages file")
	t, err := tail.TailFile(app.inputMessagesFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true, // Ensure this field is set only once
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		Poll:      true,                  // Use polling to ensure compatibility across platforms
		Logger:    tail.DiscardingLogger, // Suppress tail's own logging
	})
	if err != nil {
		logAppAction(fmt.Sprintf(ErrFileOpen, err))
		log.Fatalf(ErrFileOpen, err)
	}

	for {
		select {
		case <-ctx.Done():
			logAppAction("Tail goroutine exiting")
			return
		case line, ok := <-t.Lines:
			if !ok {
				logAppAction("Tail file closed")
				return
			}
			if line.Err != nil {
				logAppAction(fmt.Sprintf("Error reading line: %v", line.Err))
				log.Printf("Error reading line: %v", line.Err)
				continue
			}

			if len(app.rules) == 0 || matchesAnyRule(line.Text, app.rules) {
				app.addLine(line.Text)
				app.tviewApp.QueueUpdateDraw(func() {
					app.messagesView.AddItem(app.applyColorRules(line.Text), "", 0, nil)
					app.updateProgressBar()
					app.updateHelpPane()
				})
			}
		}
	}
}

// addLine adds a line to the buffer in normal mode
func (app *app) addLine(line string) {
	if !app.fullMode {
		app.linesMutex.Lock()
		defer app.linesMutex.Unlock()

		app.lines = append(app.lines, line)
		if len(app.lines) > app.maxLines {
			app.lines = app.lines[len(app.lines)-app.maxLines:]
		}
	}
}

// updateMessagesView refreshes the messagesView with the current lines
func (app *app) updateMessagesView() {
	app.messagesView.Clear()
	for _, line := range app.lines {
		displayText := app.applyColorRules(line)
		app.messagesView.AddItem(displayText, "", 0, nil)
	}
}

// updateRulesView refreshes the rulesView with the current rules
func (app *app) updateRulesView() {
	app.rulesView.Clear()
	for i, rule := range app.rules {
		prefix := ""
		if i == app.selectedRuleIndex {
			prefix = "[yellow]>[-] "
		}
		ruleDesc := ""
		if rule.Regex != nil {
			ruleDesc = fmt.Sprintf("Regex: %s", rule.Regex.String())
		} else {
			ruleDesc = fmt.Sprintf("Text: %s, CaseSensitive: %v, PartialMatch: %v", rule.Text, rule.CaseSensitive, rule.PartialMatch)
		}
		fmt.Fprintf(app.rulesView, "%s%s\n", prefix, ruleDesc)
	}
}

// applyColorRules applies color formatting to a line based on colorRules
func (app *app) applyColorRules(line string) string {
	coloredLine := line
	for _, cr := range app.colorRules {
		if cr.Regex != nil {
			coloredLine = cr.Regex.ReplaceAllStringFunc(coloredLine, func(match string) string {
				return fmt.Sprintf("%s%s[-]", cr.Color, match)
			})
		}
	}
	return coloredLine
}

// parseRule parses a rule input string into a rule struct
func parseRule(input string) (rule, error) {
	if strings.TrimSpace(input) == "" {
		return rule{}, fmt.Errorf(MsgRuleEmpty)
	}

	caseSensitive := false
	partialMatch := true
	var compiledRegex *regexp.Regexp
	var regexString string

	if strings.HasPrefix(input, "regex:") {
		pattern := strings.TrimPrefix(input, "regex:")
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return rule{}, fmt.Errorf("Invalid regex pattern: %v", err)
		}
		compiledRegex = regex
		regexString = pattern
	} else {
		if strings.HasPrefix(input, "sensitive:") {
			caseSensitive = true
			input = strings.TrimPrefix(input, "sensitive:")
		}
		if strings.HasPrefix(input, "full:") {
			partialMatch = false
			input = strings.TrimPrefix(input, "full:")
		}
	}

	return rule{
		Text:          input,
		CaseSensitive: caseSensitive,
		PartialMatch:  partialMatch,
		Regex:         compiledRegex,
		RegexString:   regexString,
	}, nil
}

// matchesAnyRule checks if a line matches any of the provided rules
func matchesAnyRule(line string, rules []rule) bool {
	for _, rule := range rules {
		if rule.Regex != nil {
			if rule.Regex.MatchString(line) {
				return true
			}
		} else {
			if rule.CaseSensitive {
				if rule.PartialMatch && strings.Contains(line, rule.Text) {
					return true
				} else if !rule.PartialMatch && line == rule.Text {
					return true
				}
			} else {
				lineLower := strings.ToLower(line)
				ruleTextLower := strings.ToLower(rule.Text)
				if rule.PartialMatch && strings.Contains(lineLower, ruleTextLower) {
					return true
				} else if !rule.PartialMatch && lineLower == ruleTextLower {
					return true
				}
			}
		}
	}
	return false
}

// rulesToStrings converts a slice of rules to their string representations
func rulesToStrings(rules []rule) []string {
	var result []string
	for _, r := range rules {
		if r.Regex != nil {
			result = append(result, fmt.Sprintf("regex:%s", r.RegexString))
		} else {
			result = append(result, fmt.Sprintf("Text: %s, CaseSensitive: %v, PartialMatch: %v", r.Text, r.CaseSensitive, r.PartialMatch))
		}
	}
	return result
}

// saveToFile saves the provided lines to a file
func saveToFile(filename string, lines []string) error {
	logAppAction(fmt.Sprintf("Saving to file: %s", filename))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf(ErrFileCreate, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf(ErrFileWrite, err)
		}
	}
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf(ErrFileWrite, err)
	}
	return nil
}

// updateProgressBar updates the progress bar based on the current mode
func (app *app) updateProgressBar() {
	if app.fullMode {
		// In full mode, calculate based on file size and offset
		fileInfo, err := os.Stat(app.inputMessagesFile)
		if err != nil {
			logAppAction(fmt.Sprintf("Error stating file: %v", err))
			app.progressBar.SetText("Error retrieving file size")
			return
		}
		fileSize := fileInfo.Size()

		app.fileMutex.Lock()
		currentOffset := app.fileOffset
		app.fileMutex.Unlock()

		if fileSize == 0 {
			app.progressBar.SetText("No logs to display")
			return
		}

		percentage := float64(currentOffset) / float64(fileSize) * 100
		if percentage < 0 {
			percentage = 0
		}
		if percentage > 100 {
			percentage = 100
		}

		// Get terminal width using golang.org/x/term
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			// Default to 80 if unable to get terminal size
			width = 80
		}

		// Set barWidth to be width -7, minimum 10 to accommodate percentage
		barWidth := width - 7
		if barWidth < 10 {
			barWidth = 10
		}

		// Calculate filled and empty
		filled := int(float64(barWidth) * (percentage / 100))
		empty := barWidth - filled

		// Ensure filled and empty are non-negative
		if filled < 0 {
			filled = 0
		}
		if empty < 0 {
			empty = 0
		}

		// Create filled and empty parts
		filledBar := strings.Repeat("█", filled)
		emptyBar := strings.Repeat("█", empty)

		// Format progress bar with colors
		progressText := fmt.Sprintf("[green]%s[-][grey]%s[-] %d%%", filledBar, emptyBar, int(percentage))

		app.progressBar.SetText(progressText)
	} else {
		// In normal mode, calculate based on number of lines
		app.linesMutex.Lock()
		totalLines := len(app.lines)
		currentIndex := app.selectedLineIndex + 1 // to make it 1-based
		app.linesMutex.Unlock()

		if totalLines == 0 {
			app.progressBar.SetText("No logs to display")
			return
		}

		// Clamp currentIndex to [1, totalLines]
		if currentIndex < 1 {
			currentIndex = 1
		}
		if currentIndex > totalLines {
			currentIndex = totalLines
		}

		// Calculate percentage
		percentage := float64(currentIndex) / float64(totalLines) * 100
		if percentage < 0 {
			percentage = 0
		}
		if percentage > 100 {
			percentage = 100
		}

		// Get terminal width using golang.org/x/term
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			// Default to 80 if unable to get terminal size
			width = 80
		}

		// Set barWidth to be width -7, minimum 10 to accommodate percentage
		barWidth := width - 7
		if barWidth < 10 {
			barWidth = 10
		}

		// Calculate filled and empty
		filled := int(float64(barWidth) * (percentage / 100))
		empty := barWidth - filled

		// Ensure filled and empty are non-negative
		if filled < 0 {
			filled = 0
		}
		if empty < 0 {
			empty = 0
		}

		// Create filled and empty parts
		filledBar := strings.Repeat("█", filled)
		emptyBar := strings.Repeat("█", empty)

		// Format progress bar with colors
		progressText := fmt.Sprintf("[green]%s[-][grey]%s[-] %d%%", filledBar, emptyBar, int(percentage))

		app.progressBar.SetText(progressText)
	}
}

// updateHelpPane updates the help pane with the current line and total lines
func (app *app) updateHelpPane() {
	// Determine current line and total lines based on mode
	var currentLine, totalLines int

	if app.fullMode {
		// In full mode, use messagesView's item count
		totalLines = app.messagesView.GetItemCount()
		currentLine = app.selectedLineIndex + 1 // 1-based indexing
	} else {
		// In normal mode, use the lines slice
		app.linesMutex.Lock()
		totalLines = len(app.lines)
		currentLine = app.selectedLineIndex + 1 // 1-based indexing
		app.linesMutex.Unlock()
	}

	// Clamp currentLine within [1, totalLines]
	if currentLine < 1 {
		currentLine = 1
	}
	if currentLine > totalLines {
		currentLine = totalLines
	}

	// Update the helpText with both help message and line count
	helpMessage := "Press 'h' for help"
	lineStatus := fmt.Sprintf(" | Line: %d / %d", currentLine, totalLines)
	app.helpText.SetText(helpMessage + lineStatus)
}

// getFullContent reads the entire file content for saving in full mode
func (app *app) getFullContent() ([]string, error) {
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		return nil, fmt.Errorf("Error opening file: %v", err)
	}
	defer file.Close()

	var lines []string
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if len(line) > 0 {
					lines = append(lines, strings.TrimRight(line, "\n"))
				}
				break
			}
			return nil, fmt.Errorf("Error reading file: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		lines = append(lines, app.applyColorRules(line))
	}
	return lines, nil
}
