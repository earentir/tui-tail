package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"ttail/logging"
	"ttail/rules"

	"github.com/gdamore/tcell/v2"
	"github.com/hpcloud/tail"
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

// App represents the application state
type App struct {
	tviewApp          *tview.Application
	messagesView      *tview.List
	rulesView         *tview.TextView
	ruleInput         *tview.InputField
	viewModal         *tview.TextView
	saveFilenameInput *tview.InputField
	progressBar       *tview.TextView
	helpText          *tview.TextView // Existing help pane
	flex              *tview.Flex
	totalLinesInFile  int
	rules             []rules.Rule
	colorRules        []rules.ColorRule
	lines             []string
	linesMutex        sync.Mutex
	selectedLineIndex int
	selectedRuleIndex int
	currentFocus      FocusState
	inputMessagesFile string
	InitialLines      int
	MaxLines          int
	RulesFile         string
	ConfigFile        string
	FullMode          bool // Indicates if --full flag is set
	fileOffset        int64
	fileMutex         sync.Mutex
	cancelFunc        context.CancelFunc
}

// NewApp creates a new application instance
// NewApp creates a new application instance
func NewApp(inputMessagesFile string, initialLines, maxLines int, rulesFile, configFile string, fullMode bool) *App {
	appInstance := &App{
		tviewApp:          tview.NewApplication(),
		inputMessagesFile: inputMessagesFile,
		rules:             []rules.Rule{},
		colorRules:        []rules.ColorRule{},
		currentFocus:      FocusMessages,
		InitialLines:      initialLines,
		MaxLines:          maxLines,
		RulesFile:         rulesFile,
		ConfigFile:        configFile,
		FullMode:          fullMode,
	}
	appInstance.initUI()
	appInstance.loadConfig()
	appInstance.loadRules()
	appInstance.updateRulesView()
	logging.LogAppAction("New app instance created")
	return appInstance
}

// Run starts the application
func (app *App) Run() error {
	logging.LogAppAction("Application run started")
	ctx, cancel := context.WithCancel(context.Background())
	app.cancelFunc = cancel
	app.setupHandlers()

	if app.FullMode {
		return app.runFullMode(ctx)
	} else {
		app.displayInitialInputMessages()
		go app.tailInputMessagesFile(ctx)
		return app.tviewApp.Run()
	}
}

// runFullMode handles the --full flag functionality
func (app *App) runFullMode(ctx context.Context) error {
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileOpen, err))
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
func (app *App) loadFullModeInitialLines(file *os.File) {
	reader := bufio.NewReader(file)
	app.linesMutex.Lock()
	app.lines = []string{} // Initialize the lines slice
	app.totalLinesInFile = 0
	app.linesMutex.Unlock()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				logging.LogAppAction(fmt.Sprintf(ErrFileRead, err))
				app.messagesView.AddItem(fmt.Sprintf(ErrFileRead, err), "", 0, nil)
				break
			}
		}
		line = strings.TrimRight(line, "\n")

		app.linesMutex.Lock()
		app.lines = append(app.lines, line)
		if len(app.lines) > app.MaxLines {
			app.lines = app.lines[1:]
		}
		app.totalLinesInFile++ // Increment total lines
		app.linesMutex.Unlock()

		app.fileMutex.Lock()
		app.fileOffset += int64(len(line)) + 1 // +1 for newline
		app.fileMutex.Unlock()
	}

	// Update the messagesView directly
	app.messagesView.Clear()
	for _, line := range app.lines {
		displayText := app.applyColorRules(line)
		app.messagesView.AddItem(displayText, "", 0, nil)
	}
	app.updateProgressBar()
	app.updateHelpPane()
}

// monitorFullModeFile monitors the file for new lines in full mode
func (app *App) monitorFullModeFile(ctx context.Context, file *os.File) {
	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			logging.LogAppAction("Full mode goroutine exiting")
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					// Wait for new data
					continue
				} else {
					logging.LogAppAction(fmt.Sprintf("Error reading line: %v", err))
					app.showMessage(fmt.Sprintf("Error reading line: %v", err), app.flex)
					continue
				}
			}
			line = strings.TrimRight(line, "\n")

			app.linesMutex.Lock()
			app.lines = append(app.lines, line)
			if len(app.lines) > app.MaxLines {
				app.lines = app.lines[1:]
			}
			app.totalLinesInFile++ // Increment total lines
			app.linesMutex.Unlock()

			app.fileMutex.Lock()
			app.fileOffset += int64(len(line)) + 1
			app.fileMutex.Unlock()

			app.tviewApp.QueueUpdateDraw(func() {
				displayText := app.applyColorRules(line)
				app.messagesView.AddItem(displayText, "", 0, nil)

				// Remove first item if necessary
				if app.messagesView.GetItemCount() > app.MaxLines {
					app.messagesView.RemoveItem(0)
				}

				app.updateProgressBar()
				app.updateHelpPane()
			})
		}
	}
}

// loadConfig loads color rules from the config file or initializes default rules
func (app *App) loadConfig() {
	if app.ConfigFile != "" {
		err := app.loadConfigFromFile(app.ConfigFile)
		if err != nil {
			logging.LogAppAction(fmt.Sprintf("Error loading config file: %v", err))
		}
	} else {
		app.initDefaultColorRules()
	}
}

// loadRules loads matching rules from the rules file
func (app *App) loadRules() {
	if app.RulesFile != "" {
		err := app.loadRulesFromFile(app.RulesFile)
		if err != nil {
			logging.LogAppAction(fmt.Sprintf("Error loading rules file: %v", err))
		} else {
			app.updateRulesView()
		}
	}
}

// initDefaultColorRules initializes default color rules
func (app *App) initDefaultColorRules() {
	// Initialize default color rules
	messagesPattern := `([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+\[\d+\])`
	app.colorRules = []rules.ColorRule{
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
func (app *App) compileColorRules() {
	for i, cr := range app.colorRules {
		regex, err := regexp.Compile(cr.Pattern)
		if err != nil {
			logging.LogAppAction(fmt.Sprintf("Error compiling color rule regex: %v", err))
			continue
		}
		app.colorRules[i].Regex = regex
	}
}

// loadConfigFromFile loads color rules from a JSON config file
func (app *App) loadConfigFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Error opening config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var config struct {
		ColorRules []rules.ColorRule `json:"color_rules"`
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
func (app *App) loadRulesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Error opening rules file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var ruleList []rules.Rule
	err = decoder.Decode(&ruleList)
	if err != nil {
		return fmt.Errorf("Error decoding rules file: %v", err)
	}

	// Compile regex patterns
	for i := range ruleList {
		if ruleList[i].RegexString != "" {
			pattern := ruleList[i].RegexString
			regex, err := regexp.Compile(pattern)
			if err != nil {
				logging.LogAppAction(fmt.Sprintf("Invalid regex in rules file: %v", err))
				// Continue loading other rules instead of returning an error
				ruleList[i].Regex = nil
				continue
			}
			ruleList[i].Regex = regex
		} else {
			ruleList[i].Regex = nil
		}
	}

	app.rules = ruleList
	logging.LogAppAction(fmt.Sprintf("Loaded %d rules from file", len(app.rules)))
	return nil
}

// displayInitialInputMessages loads the initial set of lines in normal mode
func (app *App) displayInitialInputMessages() {
	logging.LogAppAction("Displaying initial input messages")
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileOpen, err))
		app.messagesView.AddItem(fmt.Sprintf(ErrFileOpen, err), "", 0, nil)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for i := 0; i < app.InitialLines; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logging.LogAppAction(fmt.Sprintf(ErrFileRead, err))
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
func (app *App) setupHandlers() {
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
func (app *App) handleRuleInput(key tcell.Key) {
	if key == tcell.KeyEnter {
		ruleText := app.ruleInput.GetText()
		if ruleText != "" {
			rule, err := rules.ParseRule(ruleText)
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
func (app *App) handleGlobalInput(event *tcell.EventKey) *tcell.EventKey {
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
		switch event.Key() {
		case tcell.KeyUp:
			// Move selection up
			if app.selectedRuleIndex > 0 {
				app.selectedRuleIndex--
				app.updateRulesView()
			}
			return nil
		case tcell.KeyDown:
			// Move selection down
			if app.selectedRuleIndex < len(app.rules)-1 {
				app.selectedRuleIndex++
				app.updateRulesView()
			}
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 's':
				app.initiateSave()
			case 'd':
				// Delete selected rule
				app.deleteSelectedRule()
				return nil
			case 'c':
				// Toggle CaseSensitive
				app.toggleCaseSensitive()
				return nil
			case 'p':
				// Toggle PartialMatch
				app.togglePartialMatch()
				return nil
			}
		}

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

func (app *App) deleteSelectedRule() {
	if len(app.rules) == 0 {
		return
	}
	app.rules = append(app.rules[:app.selectedRuleIndex], app.rules[app.selectedRuleIndex+1:]...)
	if app.selectedRuleIndex >= len(app.rules) {
		app.selectedRuleIndex = len(app.rules) - 1
	}
	if app.selectedRuleIndex < 0 {
		app.selectedRuleIndex = 0
	}
	app.updateRulesView()
}

func (app *App) toggleCaseSensitive() {
	if len(app.rules) == 0 {
		return
	}
	rule := &app.rules[app.selectedRuleIndex]
	rule.CaseSensitive = !rule.CaseSensitive
	app.updateRulesView()
}

func (app *App) togglePartialMatch() {
	if len(app.rules) == 0 {
		return
	}
	rule := &app.rules[app.selectedRuleIndex]
	rule.PartialMatch = !rule.PartialMatch
	app.updateRulesView()
}

// cycleFocus cycles the UI focus between different panes
func (app *App) cycleFocus() {
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
	logging.LogAppAction(fmt.Sprintf("Focus cycled from %d to %d", oldFocus, app.currentFocus))
}

// viewSelectedLine displays the selected line in a modal
func (app *App) viewSelectedLine() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < app.messagesView.GetItemCount() {
		// Get the selected item's text
		mainText, _ := app.messagesView.GetItemText(app.selectedLineIndex)
		app.viewModal.Clear()
		app.viewModal.SetText(fmt.Sprintf("[white]%s[-]", mainText))
		app.tviewApp.SetRoot(app.viewModal, true)
		app.tviewApp.SetFocus(app.viewModal)
		app.currentFocus = FocusViewModal
		logging.LogAppAction(fmt.Sprintf("Viewed selected line: %d", app.selectedLineIndex))
	}
}

// closeViewModal closes the modal displaying a selected line
func (app *App) closeViewModal() {
	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

// initiateSave initiates the save operation by displaying the save input field
func (app *App) initiateSave() {
	logging.LogAppAction("Initiating save operation")
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
func (app *App) handleSaveInput() {
	filename := app.saveFilenameInput.GetText()
	app.flex.RemoveItem(app.saveFilenameInput)
	if strings.TrimSpace(filename) == "" {
		logging.LogAppAction(MsgFilenameEmpty)
		app.showMessage(MsgFilenameEmpty, app.flex)
		return
	}

	var err error

	logging.LogAppAction(fmt.Sprintf("appfocus: %v", app.currentFocus))
	switch app.currentFocus {
	case FocusMessages:
		var contentToSave []string
		if app.FullMode {
			contentToSave, err = app.getFullContent()
			if err != nil {
				logging.LogAppAction(fmt.Sprintf("Error getting full content: %v", err))
				app.showMessage(fmt.Sprintf("Error getting full content: %v", err), app.flex)
				return
			}
		} else {
			app.linesMutex.Lock()
			contentToSave = append([]string{}, app.lines...)
			app.linesMutex.Unlock()
		}
		err = app.saveToFile(filename, contentToSave)
	case FocusRulesView, FocusSaveInput:
		err = app.saveRulesToFile(filename, app.rules)
	case FocusViewModal:
		contentToSave := []string{app.viewModal.GetText(true)}
		err = app.saveToFile(filename, contentToSave)
	default:
		logging.LogAppAction(MsgInvalidContext)
		app.showMessage(MsgInvalidContext, app.flex)
		return
	}

	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileWrite, err))
		app.showMessage(fmt.Sprintf(ErrFileWrite, err), app.flex)
	} else {
		logging.LogAppAction(fmt.Sprintf(MsgFileSaved, filename))
		app.showMessage(fmt.Sprintf(MsgFileSaved, filename), app.flex)
	}
}

// saveRulesToFile saves the provided rules to a file in JSON format
func (app *App) saveRulesToFile(filename string, rules []rules.Rule) error {
	logging.LogAppAction(fmt.Sprintf("Saving rules to file: %s", filename))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf(ErrFileCreate, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Optional: For pretty printing
	err = encoder.Encode(rules)
	if err != nil {
		return fmt.Errorf(ErrFileWrite, err)
	}
	return nil
}

// cancelSave cancels the save operation and returns focus to the messages view
func (app *App) cancelSave() {
	app.flex.RemoveItem(app.saveFilenameInput)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

// deleteSelected deletes the selected line or rule
func (app *App) deleteSelected() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < app.messagesView.GetItemCount() {
		app.messagesView.RemoveItem(app.selectedLineIndex)
		if app.FullMode {
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
func (app *App) quit() {
	app.cancelFunc()
	app.tviewApp.Stop()
}

// initUI initializes the UI components and layout
func (app *App) initUI() {
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
func (app *App) showHelp() {
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
func (app *App) showMessage(message string, returnTo tview.Primitive) {
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
func (app *App) tailInputMessagesFile(ctx context.Context) {
	logging.LogAppAction("Starting to tail input messages file")
	t, err := tail.TailFile(app.inputMessagesFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true, // Ensure this field is set only once
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		Poll:      true,                  // Use polling to ensure compatibility across platforms
		Logger:    tail.DiscardingLogger, // Suppress tail's own logging
	})
	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileOpen, err))
		log.Fatalf(ErrFileOpen, err)
	}

	for {
		select {
		case <-ctx.Done():
			logging.LogAppAction("Tail goroutine exiting")
			return
		case line, ok := <-t.Lines:
			if !ok {
				logging.LogAppAction("Tail file closed")
				return
			}
			if line.Err != nil {
				logging.LogAppAction(fmt.Sprintf("Error reading line: %v", line.Err))
				log.Printf("Error reading line: %v", line.Err)
				continue
			}

			if len(app.rules) == 0 || rules.MatchesAnyRule(line.Text, app.rules) {
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
func (app *App) addLine(line string) {
	if !app.FullMode {
		app.linesMutex.Lock()
		defer app.linesMutex.Unlock()

		app.lines = append(app.lines, line)
		if len(app.lines) > app.MaxLines {
			app.lines = app.lines[len(app.lines)-app.MaxLines:]
		}
	}
}

// updateMessagesView refreshes the messagesView with the current lines
func (app *App) updateMessagesView() {
	app.messagesView.Clear()
	for _, line := range app.lines {
		displayText := app.applyColorRules(line)
		app.messagesView.AddItem(displayText, "", 0, nil)
	}
}

// updateRulesView refreshes the rulesView with the current rules
func (app *App) updateRulesView() {
	app.rulesView.Clear()
	var builder strings.Builder
	for i, rule := range app.rules {
		prefix := ""
		if i == app.selectedRuleIndex {
			prefix = "[yellow]>[-] "
		}
		ruleDesc := ""
		if rule.RegexString != "" {
			ruleDesc = fmt.Sprintf("Regex: %s", rule.RegexString)
		} else if rule.Text != "" {
			ruleDesc = fmt.Sprintf("Text: %s, CaseSensitive: %v, PartialMatch: %v", rule.Text, rule.CaseSensitive, rule.PartialMatch)
		} else {
			ruleDesc = "Invalid rule (no text or regex)"
		}
		fmt.Fprintf(&builder, "%s%s\n", prefix, ruleDesc)
	}
	app.rulesView.SetText(builder.String())
}

// applyColorRules applies color formatting to a line based on colorRules
func (app *App) applyColorRules(line string) string {
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

// saveToFile saves the provided lines to a file
func (app *App) saveToFile(filename string, lines []string) error {
	logging.LogAppAction(fmt.Sprintf("Saving to file: %s", filename))
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
func (app *App) updateProgressBar() {
	var totalLines int

	app.linesMutex.Lock()
	if app.FullMode {
		totalLines = app.totalLinesInFile
	} else {
		// In normal mode, calculate based on number of lines
		totalLines = len(app.lines)
	}
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

// }

// updateHelpPane updates the help pane with the current line and total lines
func (app *App) updateHelpPane() {
	var currentLine, totalLines int

	if app.FullMode {
		app.linesMutex.Lock()
		totalLines = app.totalLinesInFile
		offset := app.totalLinesInFile - len(app.lines)
		currentLine = offset + app.selectedLineIndex + 1
		app.linesMutex.Unlock()
	} else {
		app.linesMutex.Lock()
		totalLines = len(app.lines)
		currentLine = app.selectedLineIndex + 1
		app.linesMutex.Unlock()
	}

	// Clamp currentLine within [1, totalLines]
	if currentLine < 1 {
		currentLine = 1
	}
	if currentLine > totalLines {
		currentLine = totalLines
	}

	// Update help text
	helpMessage := "Press 'h' for help"
	lineStatus := fmt.Sprintf(" | Line: %d / %d", currentLine, totalLines)
	app.helpText.SetText(helpMessage + lineStatus)
}

// getFullContent reads the entire file content for saving in full mode
func (app *App) getFullContent() ([]string, error) {
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
