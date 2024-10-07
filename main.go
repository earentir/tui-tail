package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/hpcloud/tail"
	cli "github.com/jawher/mow.cli"
	"github.com/rivo/tview"
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
	currentFocus      int
	inputMessagesFile string
}

type rule struct {
	text          string
	caseSensitive bool
	partialMatch  bool
}

type colorRule struct {
	regex  *regexp.Regexp
	color  string
	label  string
	ruleID string
}

var (
	appLogPath string
	colorRules []colorRule
)

func main() {
	cliApp := cli.App("logviewer", "A terminal-based application for viewing and filtering log files using matching rules")
	cliApp.Version("v version", "logviewer 0.1.0")
	cliApp.LongDesc = "A terminal-based application for viewing and filtering log files using matching rules"
	inputMessagesFile := cliApp.StringArg("FILE", "", "The log file to view")

	cliApp.Action = func() {
		initAppLogging()
		logAppAction("Application started")
		app := newApp(*inputMessagesFile)
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

func applyColorRules(line string) string {
	if len(colorRules) == 0 {
		return line // Return the original line if there are no color rules
	}

	coloredLine := ""
	currentIndex := 0

	messagesRegex := colorRules[0].regex
	matches := messagesRegex.FindAllStringSubmatchIndex(line, -1)

	if matches == nil {
		return line
	}

	for _, match := range matches {
		dateStart, dateEnd := match[2], match[3]
		hostStart, hostEnd := match[4], match[5]
		serviceStart, serviceEnd := match[6], match[7]

		if dateStart > currentIndex {
			coloredLine += line[currentIndex:dateStart]
		}

		coloredLine += fmt.Sprintf("[green]%s[-]", line[dateStart:dateEnd])
		currentIndex = dateEnd

		if hostStart > currentIndex {
			coloredLine += line[currentIndex:hostStart]
		}

		coloredLine += fmt.Sprintf("[yellow]%s[-]", line[hostStart:hostEnd])
		currentIndex = hostEnd

		if serviceStart > currentIndex {
			coloredLine += line[currentIndex:serviceStart]
		}

		coloredLine += fmt.Sprintf("[blue]%s[-]", line[serviceStart:serviceEnd])
		currentIndex = serviceEnd
	}

	if currentIndex < len(line) {
		coloredLine += line[currentIndex:]
	}

	return coloredLine
}

func initAppLogging() {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error getting executable path: %v", err)
	}
	appLogPath = filepath.Join(filepath.Dir(execPath), "gtt.log")

	logFile, err := os.OpenFile(appLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func initColorRules() {
	messagesPattern := `([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+\[\d+\])`
	messagesRegex := regexp.MustCompile(messagesPattern)
	colorRules = []colorRule{
		{
			regex:  messagesRegex,
			color:  "",
			label:  "Messages",
			ruleID: "messages-matcher",
		},
	}
}

func logAppAction(action string) {
	log.Printf("Action: %s", action)
}

func matchesAnyRule(line string, rules []rule) bool {
	for _, rule := range rules {
		if rule.caseSensitive {
			if rule.partialMatch && strings.Contains(line, rule.text) {
				return true
			} else if !rule.partialMatch && line == rule.text {
				return true
			}
		} else {
			lineLower := strings.ToLower(line)
			ruleTextLower := strings.ToLower(rule.text)
			if rule.partialMatch && strings.Contains(lineLower, ruleTextLower) {
				return true
			} else if !rule.partialMatch && lineLower == ruleTextLower {
				return true
			}
		}
	}
	return false
}

func newApp(inputMessagesFile string) *app {
	app := &app{
		tviewApp:          tview.NewApplication(),
		inputMessagesFile: inputMessagesFile,
		rules:             []rule{},
		lines:             []string{},
		currentFocus:      0,
	}
	app.initUI()
	initColorRules()
	logAppAction("New app instance created")
	return app
}

func parseRule(input string) rule {
	caseSensitive := false
	partialMatch := true

	if strings.HasPrefix(input, "sensitive:") {
		caseSensitive = true
		input = strings.TrimPrefix(input, "sensitive:")
	}
	if strings.HasPrefix(input, "full:") {
		partialMatch = false
		input = strings.TrimPrefix(input, "full:")
	}

	return rule{text: input, caseSensitive: caseSensitive, partialMatch: partialMatch}
}

func rulesToStrings(rules []rule) []string {
	var result []string
	for _, r := range rules {
		result = append(result, fmt.Sprintf("Text: %s, CaseSensitive: %v, PartialMatch: %v", r.text, r.caseSensitive, r.partialMatch))
	}
	return result
}

func saveRulesToFile(filename string, rules []rule) error {
	logAppAction(fmt.Sprintf("Attempting to save rules to file: %s", filename))

	file, err := os.Create(filename)
	if err != nil {
		logAppAction(fmt.Sprintf("Error creating file for rules: %v", err))
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(rules); err != nil {
		logAppAction(fmt.Sprintf("Error encoding rules to JSON: %v", err))
		return fmt.Errorf("error encoding rules to JSON: %v", err)
	}

	logAppAction(fmt.Sprintf("Rules saved successfully to file: %s", filename))
	return nil
}

func saveToFile(filename string, lines []string) error {
	logAppAction(fmt.Sprintf("Saving to file: %s", filename))
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

func (app *app) Run() error {
	logAppAction("Application run started")
	app.setupHandlers()
	app.displayInitialInputMessages()
	go app.tailInputMessagesFile()
	return app.tviewApp.Run()
}

func (app *app) displayInitialInputMessages() {
	logAppAction("Displaying initial input messages")
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logAppAction(fmt.Sprintf("Error opening file: %v", err))
		fmt.Fprintf(app.messagesView, "Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 1024*1024) // 1MB buffer
	scanner.Buffer(buf, 1024*1024)    // Set max token size to 1MB

	for i := 0; i < 10 && scanner.Scan(); i++ {
		line := scanner.Text()
		app.lines = append(app.lines, line)
		fmt.Fprintf(app.messagesView, "%s\n", applyColorRules(line))
	}

	if err := scanner.Err(); err != nil {
		logAppAction(fmt.Sprintf("Error reading file: %v", err))
		fmt.Fprintf(app.messagesView, "Error reading file: %v\n", err)
	}
}

func (app *app) setupHandlers() {
	app.ruleInput.SetDoneFunc(app.handleRuleInput)
	app.tviewApp.SetInputCapture(app.handleGlobalInput)
}

func (app *app) cancelSave() {
	app.flex.RemoveItem(app.saveFilenameInput)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = 0
}

func (app *app) cycleFocus() {
	focusOrder := []tview.Primitive{app.messagesView, app.ruleInput, app.rulesView}
	oldFocus := app.currentFocus
	app.currentFocus = (app.currentFocus + 1) % len(focusOrder)
	app.tviewApp.SetFocus(focusOrder[app.currentFocus])
	logAppAction(fmt.Sprintf("Focus cycled from %d to %d", oldFocus, app.currentFocus))
}

func (app *app) closeViewModal() {
	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = 0
}

func (app *app) deleteSelected() {
	if app.currentFocus == 0 && app.selectedLineIndex < len(app.lines) {
		app.lines = append(app.lines[:app.selectedLineIndex], app.lines[app.selectedLineIndex+1:]...)
		if app.selectedLineIndex >= len(app.lines) {
			app.selectedLineIndex = len(app.lines) - 1
		}
		app.updateMessagesView()
	} else if app.currentFocus == 2 && app.selectedRuleIndex < len(app.rules) {
		app.rules = append(app.rules[:app.selectedRuleIndex], app.rules[app.selectedRuleIndex+1:]...)
		if app.selectedRuleIndex >= len(app.rules) {
			app.selectedRuleIndex = len(app.rules) - 1
		}
		app.updateRulesView()
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
	}

	// Handle pane-specific shortcuts
	currentFocus := app.tviewApp.GetFocus()
	switch currentFocus {
	case app.messagesView:
		switch event.Key() {
		case tcell.KeyUp:
			app.navigateUp()
		case tcell.KeyDown:
			app.navigateDown()
		case tcell.KeyEnter, tcell.KeyRune:
			if event.Key() == tcell.KeyEnter || event.Rune() == 'v' {
				app.viewSelectedLine()
			} else if event.Rune() == 's' {
				app.initiateSave()
			} else if event.Rune() == 'd' {
				app.deleteSelected()
			}
		}
	case app.rulesView:
		switch event.Key() {
		case tcell.KeyUp:
			app.navigateUp()
		case tcell.KeyDown:
			app.navigateDown()
		case tcell.KeyRune:
			switch event.Rune() {
			case 's':
				app.initiateSave()
			case 'd':
				app.deleteSelected()
			}
		}
	case app.viewModal:
		switch event.Key() {
		case tcell.KeyRune:
			switch event.Rune() {
			case 'v':
				app.closeViewModal()
				return nil
			case 's':
				app.initiateSave()
				return nil
			}
		}
	}

	// Handle quit shortcut (works everywhere except input fields)
	if event.Key() == tcell.KeyRune && event.Rune() == 'q' {
		if currentFocus != app.ruleInput && currentFocus != app.saveFilenameInput {
			app.quit()
			return nil
		}
	}

	// Pass through all other events
	return event
}

func (app *app) handleRuleInput(key tcell.Key) {
	if key == tcell.KeyEnter {
		ruleText := app.ruleInput.GetText()
		if ruleText != "" {
			rule := parseRule(ruleText)
			app.rules = append(app.rules, rule)
			app.updateRulesView()
			app.ruleInput.SetText("")
		}
	}
}

func (app *app) handleSaveInput() {
	logAppAction("Handling save input")
	filename := app.saveFilenameInput.GetText()
	app.flex.RemoveItem(app.saveFilenameInput)

	if filename == "" {
		logAppAction("Save cancelled: empty filename")
		return
	}

	var contentToSave []string
	switch app.currentFocus {
	case 0:
		contentToSave = app.lines
	case 2:
		contentToSave = rulesToStrings(app.rules)
	default:
		if app.tviewApp.GetFocus() == app.viewModal {
			contentToSave = []string{app.viewModal.GetText(true)}
		} else {
			logAppAction("Invalid save context")
			return
		}
	}

	err := saveToFile(filename, contentToSave)
	if err != nil {
		logAppAction(fmt.Sprintf("Error saving file: %v", err))
		app.showMessage(fmt.Sprintf("Error saving file: %v", err), app.flex)
	} else {
		logAppAction(fmt.Sprintf("File saved successfully: %s", filename))
		app.showMessage(fmt.Sprintf("File saved successfully: %s", filename), app.flex)
	}
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

	app.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(app.messagesView, 0, 8, false).
		AddItem(app.ruleInput, 1, 0, false).
		AddItem(app.rulesView, 0, 2, false)

	app.tviewApp.SetRoot(app.flex, true)
	app.tviewApp.SetFocus(app.messagesView)
	app.currentFocus = 0
}

func (app *app) navigateDown() {
	if app.currentFocus == 0 && app.selectedLineIndex < len(app.lines)-1 {
		app.selectedLineIndex++
		app.updateMessagesView()
	}
}

func (app *app) navigateUp() {
	if app.currentFocus == 0 && app.selectedLineIndex > 0 {
		app.selectedLineIndex--
		app.updateMessagesView()
	}
}

func (app *app) performSave(filename string) {
	logAppAction(fmt.Sprintf("Performing save with filename: %s", filename))

	if filename == "" {
		logAppAction("Save cancelled: empty filename")
		app.showMessage("Save cancelled: empty filename", app.flex)
		return
	}

	var contentToSave []string

	logAppAction(fmt.Sprintf("Current focus: %d", app.currentFocus))
	switch app.currentFocus {
	case 0:
		logAppAction("Preparing to save messages")
		contentToSave = app.lines
	case 2:
		logAppAction("Preparing to save rules")
		contentToSave = rulesToStrings(app.rules)
	default:
		if app.tviewApp.GetFocus() == app.viewModal {
			logAppAction("Preparing to save viewed line")
			contentToSave = []string{app.viewModal.GetText(true)}
		} else {
			logAppAction("Invalid save context")
			app.showMessage("Cannot save in current context", app.flex)
			return
		}
	}

	logAppAction(fmt.Sprintf("Calling saveToFile with filename: %s", filename))
	err := saveToFile(filename, contentToSave)
	if err != nil {
		logAppAction(fmt.Sprintf("Error saving file: %v", err))
		app.showMessage(fmt.Sprintf("Error saving file: %v", err), app.flex)
	} else {
		logAppAction(fmt.Sprintf("File saved successfully: %s", filename))
		app.showMessage(fmt.Sprintf("File saved successfully: %s", filename), app.flex)
	}
}

func (app *app) showMessage(message string, returnTo tview.Primitive) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			app.tviewApp.SetRoot(returnTo, true)
		})
	app.tviewApp.SetRoot(modal, true)
}

func (app *app) tailInputMessagesFile() {
	logAppAction("Starting to tail input messages file")
	t, err := tail.TailFile(app.inputMessagesFile, tail.Config{
		Follow:   true,
		ReOpen:   true,
		Location: &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
	})
	if err != nil {
		logAppAction(fmt.Sprintf("Error opening file: %v", err))
		log.Fatalf("Error opening file: %v", err)
	}

	for line := range t.Lines {
		if line.Err != nil {
			logAppAction(fmt.Sprintf("Error reading line: %v", line.Err))
			log.Printf("Error reading line: %v", line.Err)
			continue
		}

		if len(app.rules) == 0 || matchesAnyRule(line.Text, app.rules) {
			app.lines = append(app.lines, line.Text)
			app.tviewApp.QueueUpdateDraw(func() {
				fmt.Fprintln(app.messagesView, applyColorRules(line.Text))
			})
		}
	}
}

func (app *app) toggleViewModal() {
	if app.currentFocus == 0 && app.selectedLineIndex < len(app.lines) {
		app.viewSelectedLine()
		logAppAction("Opened view modal")
	} else if app.tviewApp.GetFocus() == app.viewModal {
		app.closeViewModal()
		logAppAction("Closed view modal")
	}
}

func (app *app) updateMessagesView() {
	app.messagesView.Clear()
	for i, line := range app.lines {
		prefix := "  "
		if i == app.selectedLineIndex {
			prefix = "> "
		}
		fmt.Fprintf(app.messagesView, "%s%s\n", prefix, applyColorRules(line))
	}
}

func (app *app) updateRulesView() {
	app.rulesView.Clear()
	for i, rule := range app.rules {
		prefix := "  "
		if i == app.selectedRuleIndex {
			prefix = "> "
		}
		fmt.Fprintf(app.rulesView, "%sText: %s, CaseSensitive: %v, PartialMatch: %v\n", prefix, rule.text, rule.caseSensitive, rule.partialMatch)
	}
}

func (app *app) viewSelectedLine() {
	if app.currentFocus == 0 && app.selectedLineIndex < len(app.lines) {
		app.viewModal.Clear()
		app.viewModal.SetText(fmt.Sprintf("[white]%s[-]", applyColorRules(app.lines[app.selectedLineIndex])))
		app.tviewApp.SetRoot(app.viewModal, true)
		logAppAction(fmt.Sprintf("Viewed selected line: %d", app.selectedLineIndex))
	}
}

func (app *app) quit() {
	if app.currentFocus == 0 || app.currentFocus == 2 {
		app.tviewApp.Stop()
	}
}
