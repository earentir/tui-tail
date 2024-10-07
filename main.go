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

type app struct {
	tviewApp          *tview.Application
	messagesView      *tview.TextView
	rulesView         *tview.TextView
	ruleInput         *tview.InputField
	viewModal         *tview.TextView
	saveFilenameInput *tview.InputField
	flex              *tview.Flex
	rules             []rule
	lines             []string
	selectedLineIndex int
	selectedRuleIndex int
	currentFocus      FocusState
	inputMessagesFile string
	colorRules        []colorRule
	linesMutex        sync.Mutex
	cancelFunc        context.CancelFunc
	initialLines      int
	maxLines          int
	rulesFile         string
	configFile        string
}

type rule struct {
	Text          string         `json:"text"`
	CaseSensitive bool           `json:"caseSensitive"`
	PartialMatch  bool           `json:"partialMatch"`
	Regex         *regexp.Regexp `json:"-"`
	RegexString   string         `json:"regex"` // For JSON marshalling/unmarshalling
}

type colorRule struct {
	Pattern string         `json:"pattern"`
	Regex   *regexp.Regexp `json:"-"`
	Color   string         `json:"color"`
	Label   string         `json:"label"`
	RuleID  string         `json:"rule_id"`
}

func main() {
	cliApp := cli.App("logviewer", "A terminal-based application for viewing and filtering log files using matching rules")
	cliApp.Version("v version", "logviewer 0.1.0")
	cliApp.LongDesc = "A terminal-based application for viewing and filtering log files using matching rules"

	inputMessagesFile := cliApp.StringArg("FILE", "", "The log file to view")

	initialLines := cliApp.IntOpt("n num-lines", DefaultInitialLines, "Number of initial lines to load")
	maxLines := cliApp.IntOpt("max-lines", DefaultMaxLines, "Maximum number of lines to keep in memory")
	rulesFile := cliApp.StringOpt("r rules-file", "", "JSON file containing matching rules to load at startup")
	configFile := cliApp.StringOpt("c config-file", "", "JSON configuration file for color rules and settings")

	cliApp.Action = func() {
		initAppLogging()
		logAppAction(MsgAppStarted)
		defer logAppAction(MsgAppStopped)
		app := newApp(*inputMessagesFile)
		app.initialLines = *initialLines
		app.maxLines = *maxLines
		app.rulesFile = *rulesFile
		app.configFile = *configFile

		if err := app.Run(); err != nil {
			logAppAction(fmt.Sprintf("Error running application: %v", err))
			log.Fatalf("Error running application: %v", err)
		}
	}

	if err := cliApp.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

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

func logAppAction(action string) {
	log.Printf("Action: %s", action)
}

func newApp(inputMessagesFile string) *app {
	app := &app{
		tviewApp:          tview.NewApplication(),
		inputMessagesFile: inputMessagesFile,
		rules:             []rule{},
		lines:             []string{},
		currentFocus:      FocusMessages,
		colorRules:        []colorRule{},
		initialLines:      DefaultInitialLines,
		maxLines:          DefaultMaxLines,
	}
	app.initUI()
	app.loadConfig()
	app.loadRules()
	logAppAction("New app instance created")
	return app
}

func (app *app) Run() error {
	logAppAction("Application run started")
	ctx, cancel := context.WithCancel(context.Background())
	app.cancelFunc = cancel
	app.setupHandlers()
	app.displayInitialInputMessages()
	go app.tailInputMessagesFile(ctx)
	return app.tviewApp.Run()
}

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

func (app *app) loadRules() {
	if app.rulesFile != "" {
		err := app.loadRulesFromFile(app.rulesFile)
		if err != nil {
			logAppAction(fmt.Sprintf("Error loading rules file: %v", err))
		}
	}
}

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

func (app *app) displayInitialInputMessages() {
	logAppAction("Displaying initial input messages")
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logAppAction(fmt.Sprintf(ErrFileOpen, err))
		fmt.Fprintf(app.messagesView, ErrFileOpen+"\n", err)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for i := 0; i < app.initialLines; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logAppAction(fmt.Sprintf(ErrFileRead, err))
				fmt.Fprintf(app.messagesView, ErrFileRead+"\n", err)
			}
			break
		}
		line = strings.TrimRight(line, "\n")
		app.addLine(line)
		fmt.Fprintf(app.messagesView, "%s\n", app.applyColorRules(line))
	}
}

func (app *app) setupHandlers() {
	app.ruleInput.SetDoneFunc(app.handleRuleInput)
	app.tviewApp.SetInputCapture(app.handleGlobalInput)
}

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
	currentFocus := app.tviewApp.GetFocus()
	switch currentFocus {
	case app.messagesView:
		switch event.Key() {
		case tcell.KeyUp:
			app.navigateUp()
			return nil
		case tcell.KeyDown:
			app.navigateDown()
			return nil
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
	case app.rulesView:
		switch event.Key() {
		case tcell.KeyUp:
			app.navigateUp()
			return nil
		case tcell.KeyDown:
			app.navigateDown()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case keyBindings["save"]:
				app.initiateSave()
			case keyBindings["delete"]:
				app.deleteSelected()
			}
			return nil
		}
	case app.viewModal:
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

func (app *app) cycleFocus() {
	focusOrder := []tview.Primitive{app.messagesView, app.ruleInput, app.rulesView}
	oldFocus := app.currentFocus
	app.currentFocus = (app.currentFocus + 1) % FocusState(len(focusOrder))
	app.tviewApp.SetFocus(focusOrder[app.currentFocus])
	logAppAction(fmt.Sprintf("Focus cycled from %d to %d", oldFocus, app.currentFocus))
}

func (app *app) navigateUp() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex > 0 {
		app.selectedLineIndex--
		app.updateMessagesView()
	} else if app.currentFocus == FocusRulesView && app.selectedRuleIndex > 0 {
		app.selectedRuleIndex--
		app.updateRulesView()
	}
}

func (app *app) navigateDown() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < len(app.lines)-1 {
		app.selectedLineIndex++
		app.updateMessagesView()
	} else if app.currentFocus == FocusRulesView && app.selectedRuleIndex < len(app.rules)-1 {
		app.selectedRuleIndex++
		app.updateRulesView()
	}
}

func (app *app) viewSelectedLine() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < len(app.lines) {
		app.viewModal.Clear()
		app.viewModal.SetText(fmt.Sprintf("[white]%s[-]", app.applyColorRules(app.lines[app.selectedLineIndex])))
		app.tviewApp.SetRoot(app.viewModal, true)
		app.currentFocus = FocusViewModal
		logAppAction(fmt.Sprintf("Viewed selected line: %d", app.selectedLineIndex))
	}
}

func (app *app) closeViewModal() {
	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

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

func (app *app) handleSaveInput() {
	filename := app.saveFilenameInput.GetText()
	app.flex.RemoveItem(app.saveFilenameInput)
	if strings.TrimSpace(filename) == "" {
		logAppAction(MsgFilenameEmpty)
		app.showMessage(MsgFilenameEmpty, app.flex)
		return
	}

	var contentToSave []string
	switch app.currentFocus {
	case FocusMessages:
		contentToSave = app.lines
	case FocusRulesView:
		contentToSave = rulesToStrings(app.rules)
	case FocusViewModal:
		contentToSave = []string{app.viewModal.GetText(true)}
	default:
		logAppAction(MsgInvalidContext)
		app.showMessage(MsgInvalidContext, app.flex)
		return
	}

	err := saveToFile(filename, contentToSave)
	if err != nil {
		logAppAction(fmt.Sprintf(ErrFileWrite, err))
		app.showMessage(fmt.Sprintf(ErrFileWrite, err), app.flex)
	} else {
		logAppAction(fmt.Sprintf(MsgFileSaved, filename))
		app.showMessage(fmt.Sprintf(MsgFileSaved, filename), app.flex)
	}
}

func (app *app) cancelSave() {
	app.flex.RemoveItem(app.saveFilenameInput)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

func (app *app) deleteSelected() {
	if app.currentFocus == FocusMessages && app.selectedLineIndex < len(app.lines) {
		app.linesMutex.Lock()
		defer app.linesMutex.Unlock()
		app.lines = append(app.lines[:app.selectedLineIndex], app.lines[app.selectedLineIndex+1:]...)
		if app.selectedLineIndex >= len(app.lines) {
			app.selectedLineIndex = len(app.lines) - 1
		}
		app.updateMessagesView()
	} else if app.currentFocus == FocusRulesView && app.selectedRuleIndex < len(app.rules) {
		app.rules = append(app.rules[:app.selectedRuleIndex], app.rules[app.selectedRuleIndex+1:]...)
		if app.selectedRuleIndex >= len(app.rules) {
			app.selectedRuleIndex = len(app.rules) - 1
		}
		app.updateRulesView()
	}
}

func (app *app) quit() {
	app.cancelFunc()
	app.tviewApp.Stop()
}

func (app *app) initUI() {
	app.messagesView = tview.NewTextView()
	app.messagesView.
		SetDynamicColors(true).
		SetRegions(true).
		SetBorder(true).
		SetTitle("Messages")

	app.rulesView = tview.NewTextView()
	app.rulesView.
		SetDynamicColors(true).
		SetBorder(true).
		SetTitle("Matching Rules")

	app.ruleInput = tview.NewInputField().
		SetLabel("Add Matching Rule: ").
		SetFieldWidth(30)

	app.viewModal = tview.NewTextView()
	app.viewModal.
		SetDynamicColors(true).
		SetWordWrap(true).
		SetBackgroundColor(tcell.ColorDarkGray)
	app.viewModal.
		SetBorder(true).
		SetTitle("View Line - Press 'v', 'Enter', or 'Esc' to close").
		SetTitleAlign(tview.AlignLeft)

	app.saveFilenameInput = tview.NewInputField().
		SetLabel("Save as: ").
		SetFieldWidth(30)

	// Help text at the bottom
	helpText := tview.NewTextView().
		SetText("Press 'h' for help").
		SetTextColor(tcell.ColorYellow)

	app.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(app.messagesView, 0, 8, false).
		AddItem(app.ruleInput, 1, 0, false).
		AddItem(app.rulesView, 0, 2, false).
		AddItem(helpText, 1, 0, false)

	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = FocusMessages
}

func (app *app) showHelp() {
	helpText := `
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
`
	app.showMessage(helpText, app.flex)
}

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

func (app *app) tailInputMessagesFile(ctx context.Context) {
	logAppAction("Starting to tail input messages file")
	t, err := tail.TailFile(app.inputMessagesFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
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
					fmt.Fprintln(app.messagesView, app.applyColorRules(line.Text))
				})
			}
		}
	}
}

func (app *app) addLine(line string) {
	app.linesMutex.Lock()
	defer app.linesMutex.Unlock()

	app.lines = append(app.lines, line)
	if len(app.lines) > app.maxLines {
		app.lines = app.lines[len(app.lines)-app.maxLines:]
	}
}

func (app *app) updateMessagesView() {
	app.messagesView.Clear()
	for i, line := range app.lines {
		prefix := "  "
		if i == app.selectedLineIndex {
			prefix = "[yellow]>[-] "
			line = fmt.Sprintf("[black:white]%s[-:-]", line)
		}
		fmt.Fprintf(app.messagesView, "%s%s\n", prefix, app.applyColorRules(line))
	}
}

func (app *app) updateRulesView() {
	app.rulesView.Clear()
	for i, rule := range app.rules {
		prefix := "  "
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
