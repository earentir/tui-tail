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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ttail/logging"
	"ttail/rules"

	"github.com/gdamore/tcell/v2"
	"github.com/hpcloud/tail"
	"github.com/hpcloud/tail/watch"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

// Multi-file layout: each file region has 1 header line + at least 3 content lines.
const (
	LinesPerFileRegion   = 4
	MinNonMessagesLines = 7
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
	"quit":      'q',
	"save":      's',
	"view":      'v',
	"delete":    'd',
	"help":      'h',
	"follow":    'f',
	"search":    '/',
	"next":      'n',
	"sensitive": 'c',
	"partial":   'p',
	"addRule":   'r',
}

// FocusState represents the current focus in the UI
type FocusState int

const (
	focusMessages FocusState = iota
	focusRuleInput
	focusRulesView
	focusSaveInput
	focusViewModal
	focusSearchInput
)

// overlayRoot draws the main flex full-screen and optionally a popup centered on top (half screen width).
// The TUI stays visible; popup does not blank the background. Keys: when popup has focus target, forward to it;
// when text popup is open, Esc runs escapeHandler; else forward to getFocus (list).
type overlayRoot struct {
	*tview.Box
	flex          *tview.Flex
	popup         tview.Primitive
	popupFocus    tview.Primitive // when set, keys go to this (e.g. search/rule input)
	popupHeight   int
	getFocus      func() tview.Primitive
	escapeHandler func() // when set, Esc calls this (for help/view line close)
}

func newOverlayRoot(flex *tview.Flex) *overlayRoot {
	return &overlayRoot{Box: tview.NewBox(), flex: flex, popupHeight: 3}
}

func (o *overlayRoot) SetGetFocus(fn func() tview.Primitive) { o.getFocus = fn }
func (o *overlayRoot) SetEscapeHandler(fn func())             { o.escapeHandler = fn }

func (o *overlayRoot) SetPopupWithFocus(popup, focus tview.Primitive, height int) {
	o.popup = popup
	o.popupFocus = focus
	if height > 0 {
		o.popupHeight = height
	}
}

func (o *overlayRoot) SetTextPopup(popup tview.Primitive, height int) {
	o.popup = popup
	o.popupFocus = nil
	if height > 0 {
		o.popupHeight = height
	}
}

func (o *overlayRoot) ClearPopup() {
	o.popup = nil
	o.popupFocus = nil
	o.popupHeight = 3
}

func (o *overlayRoot) HasPopup() bool { return o.popup != nil }

func (o *overlayRoot) SetRect(x, y, w, h int) {
	o.Box.SetRect(x, y, w, h)
	o.flex.SetRect(x, y, w, h)
	if o.popup != nil {
		pw := w / 2
		if pw < 40 {
			pw = 40
		}
		if pw > w-4 {
			pw = w - 4
		}
		ph := o.popupHeight
		px := x + (w-pw)/2
		py := y + (h-ph)/2
		if py < y {
			py = y
		}
		o.popup.SetRect(px, py, pw, ph)
	}
}

func (o *overlayRoot) Draw(screen tcell.Screen) {
	x, y, w, h := o.Box.GetRect()
	o.flex.SetRect(x, y, w, h)
	o.flex.Draw(screen)
	if o.popup != nil {
		pw := w / 2
		if pw < 40 {
			pw = 40
		}
		if pw > w-4 {
			pw = w - 4
		}
		ph := o.popupHeight
		px := x + (w-pw)/2
		py := y + (h-ph)/2
		if py < y {
			py = y
		}
		o.popup.SetRect(px, py, pw, ph)
		o.popup.Draw(screen)
	}
}

func (o *overlayRoot) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return func(event *tcell.EventKey, setFocus func(tview.Primitive)) {
		if event.Key() == tcell.KeyEscape && o.escapeHandler != nil {
			o.escapeHandler()
			return
		}
		if o.popup != nil && o.popupFocus != nil {
			if h := o.popupFocus.InputHandler(); h != nil {
				h(event, setFocus)
			}
			return
		}
		if o.popup == nil && o.getFocus != nil {
			p := o.getFocus()
			if p != nil && p.InputHandler() != nil {
				p.InputHandler()(event, setFocus)
			}
		}
	}
}

// FileRegion holds state for one file in multi-file mode.
type FileRegion struct {
	Path             string
	Header           *tview.TextView // one-line header (path), no box border
	List             *tview.List
	Lines            []string
	LinesMutex       sync.Mutex
	TotalLinesInFile int
	FileOffset       int64
	FileMutex        sync.Mutex
}

// App represents the application state
type App struct {
	tviewApp           *tview.Application
	messagesView       *tview.List
	multiFileView      *tview.Flex
	fileRegions        []*FileRegion
	focusedRegionIndex int
	rulesView          *tview.TextView
	ruleInput          *tview.InputField
	viewModal          *tview.TextView
	saveFilenameInput  *tview.InputField
	searchInput        *tview.InputField
	progressBar        *tview.TextView
	helpText           *tview.TextView
	flex               *tview.Flex
	rootOverlay        *overlayRoot // root: flex full-screen + optional centered popup (TUI visible, half-width popup)
	textPopupOnClose   func()       // when non-nil, Esc closes the generic text popup
	totalLinesInFile   int
	rules              []rules.Rule
	colorRules         []rules.ColorRule
	lines              []string
	linesMutex         sync.Mutex
	selectedLineIndex  int
	selectedRuleIndex  int
	currentFocus       FocusState
	inputFiles         []string
	inputMessagesFile  string
	InitialLines       int
	MaxLines           int
	RulesFile          string
	ConfigFile         string
	logFile            string
	FullMode           bool
	fileOffset         int64
	fileMutex          sync.Mutex
	cancelFunc         context.CancelFunc
	runCtx             context.Context
	followMode         bool
	tailStarted        bool
	Retry              bool
	FollowName         bool
	HeadMode           bool
	BytesLast          int64 // last N bytes (0 = not used)
	BytesFrom          int64 // from byte N to end (0 = not used)
	LinesFrom          int     // from line N to end, skip first N-1 (0 = not used)
	Pid                int     // if > 0 and following, exit when this process dies (GNU tail --pid)
	SleepInterval      float64 // if > 0 and following, poll file every N seconds (GNU tail -s)
	ZeroTerminated     bool    // input is NUL-delimited (GNU tail -z)
	searchTerm         string
	searchResults      []int
	currentSearchIndex int
}

// parseBytesSpec parses a bytes spec like "100" (last N) or "+100" (from byte N).
// Returns (bytesLast, bytesFrom); both 0 means line mode.
func parseBytesSpec(s string) (bytesLast, bytesFrom int64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0
	}
	if strings.HasPrefix(s, "+") {
		n, err := strconv.ParseInt(strings.TrimPrefix(s, "+"), 10, 64)
		if err != nil || n < 1 {
			return 0, 0
		}
		return 0, n
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, 0
	}
	return n, 0
}

// NewApp creates a new application instance. inputFiles must have at least one path.
func NewApp(inputFiles []string, initialLines, maxLines int, rulesFile, configFile string, fullMode bool, headMode bool, logFile string, follow bool, followName bool, retry bool, bytesStr string, linesFrom int, pid int, sleepInterval float64, zeroTerminated bool) *App {
	bytesLast, bytesFrom := parseBytesSpec(bytesStr)
	appInstance := &App{
		tviewApp:          tview.NewApplication(),
		inputFiles:        inputFiles,
		inputMessagesFile: inputFiles[0],
		rules:             []rules.Rule{},
		colorRules:        []rules.ColorRule{},
		currentFocus:      focusMessages,
		InitialLines:      initialLines,
		MaxLines:          maxLines,
		RulesFile:         rulesFile,
		ConfigFile:        configFile,
		FullMode:          fullMode,
		HeadMode:          headMode,
		logFile:           logFile,
		followMode:        follow,
		Retry:             retry,
		FollowName:        followName,
		BytesLast:         bytesLast,
		BytesFrom:         bytesFrom,
		LinesFrom:         linesFrom,
		Pid:               pid,
		SleepInterval:     sleepInterval,
		ZeroTerminated:    zeroTerminated,
	}
	appInstance.initUI()
	appInstance.loadConfig()
	appInstance.loadRules()
	appInstance.updateRulesView()
	logging.LogAppAction("New app instance created")
	return appInstance
}

// updateMessagesPaneTitle updates the title of the messages pane based on followMode
func (app *App) updateMessagesPaneTitle() {
	if app.messagesView == nil {
		return
	}
	if app.followMode {
		app.messagesView.SetTitle("[green]Messages[-]")
	} else {
		app.messagesView.SetTitle("[white]Messages[-]")
	}
}

// currentMessagesView returns the list widget that has focus in the messages area (single-file or focused region).
func (app *App) currentMessagesView() *tview.List {
	if app.messagesView != nil {
		return app.messagesView
	}
	if len(app.fileRegions) > 0 && app.focusedRegionIndex >= 0 && app.focusedRegionIndex < len(app.fileRegions) {
		return app.fileRegions[app.focusedRegionIndex].List
	}
	return nil
}

// currentRegion returns the focused file region in multi-file mode, or nil in single-file mode.
func (app *App) currentRegion() *FileRegion {
	if len(app.fileRegions) == 0 {
		return nil
	}
	if app.focusedRegionIndex < 0 || app.focusedRegionIndex >= len(app.fileRegions) {
		return nil
	}
	return app.fileRegions[app.focusedRegionIndex]
}

// currentLinesAndMutex returns the current lines slice and its mutex (for single-file or focused region).
func (app *App) currentLinesAndMutex() (*[]string, *sync.Mutex) {
	if r := app.currentRegion(); r != nil {
		return &r.Lines, &r.LinesMutex
	}
	return &app.lines, &app.linesMutex
}

// isMultiFile returns true when tailing multiple files.
func (app *App) isMultiFile() bool {
	return len(app.inputFiles) > 1
}

// Run starts the application
func (app *App) Run() error {
	logging.LogAppAction("Application run started")
	ctx, cancel := context.WithCancel(context.Background())
	app.cancelFunc = cancel
	app.runCtx = ctx
	app.setupHandlers()

	// Same layout for 1 or N files: need N×4 lines
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return fmt.Errorf("cannot get terminal size: %w", err)
	}
	required := len(app.inputFiles) * LinesPerFileRegion
	available := height - MinNonMessagesLines
	if available < required {
		return fmt.Errorf("cannot fit %d files: need %d lines (4 per file), only %d available; reduce number of files or increase terminal height", len(app.inputFiles), required, available)
	}

	if app.Retry {
		if err := app.waitForFileToExist(ctx); err != nil {
			return err
		}
	}

	if app.FullMode {
		return app.runFullMode(ctx)
	}
	app.displayInitialInputMessages()
	if app.followMode {
		app.tailStarted = true
		for _, region := range app.fileRegions {
			if app.ZeroTerminated {
				go app.tailInputMessagesFileZeroTerminatedForRegion(ctx, region)
			} else {
				go app.tailInputMessagesFileForRegion(ctx, region)
			}
		}
		if app.Pid > 0 {
			go app.monitorPid(ctx)
		}
	}
	return app.tviewApp.Run()
}

// processExists reports whether the process with the given PID exists (Unix: kill(pid, 0)).
// On Windows this may not be reliable; --pid is primarily for Unix.
func processExists(pid int) bool {
	return syscall.Kill(pid, syscall.Signal(0)) == nil
}

// monitorPid exits the app when the process with app.Pid dies (GNU tail --pid).
func (app *App) monitorPid(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !processExists(app.Pid) {
				logging.LogAppAction(fmt.Sprintf("Process %d exited, stopping", app.Pid))
				app.tviewApp.QueueUpdate(func() { app.tviewApp.Stop() })
				return
			}
		}
	}
}

// lineDelim returns the line delimiter for reading: '\n' or '\x00' for zero-terminated.
func (app *App) lineDelim() byte {
	if app.ZeroTerminated {
		return '\x00'
	}
	return '\n'
}

// waitForFileToExist blocks until the input file(s) exist or ctx is cancelled.
// Used when --retry is set. For multi-file, waits for all files to exist.
func (app *App) waitForFileToExist(ctx context.Context) error {
	const pollInterval = 500 * time.Millisecond
	files := app.inputFiles
	for {
		allExist := true
		for _, path := range files {
			_, err := os.Stat(path)
			if err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf(ErrFileOpen, err)
				}
				allExist = false
				break
			}
		}
		if allExist {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// runFullMode handles the --full flag functionality (single file, first region).
func (app *App) runFullMode(ctx context.Context) error {
	if len(app.fileRegions) == 0 {
		return fmt.Errorf("no file region")
	}
	region := app.fileRegions[0]
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileOpen, err))
		region.List.AddItem(fmt.Sprintf(ErrFileOpen, err), "", 0, nil)
		return err
	}
	defer file.Close()

	logging.LogAppAction("Run in Full Mode")

	region.FileMutex.Lock()
	region.FileOffset = 0
	region.FileMutex.Unlock()

	app.loadFullModeInitialLines(file, region)

	go app.monitorFullModeFile(ctx, file, region)

	return app.tviewApp.Run()
}

// loadFullModeInitialLines loads the initial set of lines in full mode into the given region.
func (app *App) loadFullModeInitialLines(file *os.File, region *FileRegion) {
	region.LinesMutex.Lock()
	region.Lines = []string{}
	region.TotalLinesInFile = 0
	region.LinesMutex.Unlock()

	if app.HeadMode {
		delim := app.lineDelim()
		reader := bufio.NewReader(file)
		for {
			line, err := reader.ReadString(delim)
			if err != nil {
				if err == io.EOF {
					break
				}
				logging.LogAppAction(fmt.Sprintf(ErrFileRead, err))
				region.List.AddItem(fmt.Sprintf(ErrFileRead, err), "", 0, nil)
				break
			}
			line = strings.TrimSuffix(line, string(delim))
			if delim == '\n' {
				line = strings.TrimRight(line, "\r")
			}

			region.LinesMutex.Lock()
			region.Lines = append(region.Lines, line)
			region.TotalLinesInFile++
			region.LinesMutex.Unlock()

			if region.TotalLinesInFile >= app.InitialLines {
				break
			}
		}
		logging.LogAppAction("Head Mode & Full Mode, Loaded initial lines")
	} else {
		lines, err := app.readLastNLines(app.inputMessagesFile, app.InitialLines, app.lineDelim())
		if err != nil {
			logging.LogAppAction(fmt.Sprintf("Error reading last N lines: %v", err))
			region.List.AddItem(fmt.Sprintf("Error reading last N lines: %v", err), "", 0, nil)
			return
		}

		region.LinesMutex.Lock()
		region.Lines = lines
		region.TotalLinesInFile = len(lines)
		region.LinesMutex.Unlock()

		logging.LogAppAction("Normal Mode & Full Mode, Loaded initial lines")
	}

	region.List.Clear()
	for _, line := range region.Lines {
		region.List.AddItem(app.applyColorRules(line), "", 0, nil)
	}
	if app.followMode {
		region.List.SetCurrentItem(region.List.GetItemCount() - 1)
	}
	app.updateProgressBar()
	app.updateHelpPane()
}

// monitorFullModeFile monitors the file for new lines in full mode, updating the given region.
func (app *App) monitorFullModeFile(ctx context.Context, file *os.File, region *FileRegion) {
	delim := app.lineDelim()
	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			logging.LogAppAction("Full mode goroutine exiting")
			return
		default:
			line, err := reader.ReadString(delim)
			if err != nil {
				if err == io.EOF {
					continue
				}
				logging.LogAppAction(fmt.Sprintf("Error reading line: %v", err))
				app.showMessage(fmt.Sprintf("Error reading line: %v", err), app.rootOverlay)
				continue
			}
			line = strings.TrimSuffix(line, string(delim))
			if delim == '\n' {
				line = strings.TrimRight(line, "\r")
			}

			region.LinesMutex.Lock()
			region.Lines = append(region.Lines, line)
			if len(region.Lines) > app.MaxLines {
				region.Lines = region.Lines[1:]
			}
			region.TotalLinesInFile++
			region.LinesMutex.Unlock()

			region.FileMutex.Lock()
			region.FileOffset += int64(len(line)) + 1
			region.FileMutex.Unlock()

			app.tviewApp.QueueUpdateDraw(func() {
				region.List.AddItem(app.applyColorRules(line), "", 0, nil)
				if region.List.GetItemCount() > app.MaxLines {
					region.List.RemoveItem(0)
				}
				app.updateProgressBar()
				app.updateHelpPane()
				if app.followMode {
					region.List.SetCurrentItem(region.List.GetItemCount() - 1)
				}
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
	logging.LogAppAction("Colour Rules loaded")
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

// displayInitialInputMessages loads the initial set of lines in normal mode.
// Same path for 1 or N files: one header+list region per file.
func (app *App) displayInitialInputMessages() {
	logging.LogAppAction("Displaying initial input messages")
	for _, region := range app.fileRegions {
		app.displayInitialFile(region)
	}
	app.updateProgressBar()
	app.updateHelpPane()
}

// displayInitialFile loads initial lines for one file into the given region (multi-file mode).
func (app *App) displayInitialFile(region *FileRegion) {
	path := region.Path
	var lines []string
	var err error

	switch {
	case app.BytesLast > 0:
		lines, err = app.readLastNBytes(path, app.BytesLast)
	case app.BytesFrom > 0:
		lines, err = app.readFromByte(path, app.BytesFrom)
	case app.LinesFrom > 0:
		lines, err = app.readFromLineN(path, app.LinesFrom, app.lineDelim())
	default:
		if app.HeadMode {
			delim := app.lineDelim()
			file, openErr := os.Open(path)
			if openErr != nil {
				region.List.AddItem(fmt.Sprintf(ErrFileOpen, openErr), "", 0, nil)
				return
			}
			reader := bufio.NewReader(file)
			for i := 0; i < app.InitialLines; i++ {
				line, readErr := reader.ReadString(delim)
				if readErr != nil {
					break
				}
				line = strings.TrimSuffix(line, string(delim))
				if delim == '\n' {
					line = strings.TrimRight(line, "\r")
				}
				lines = append(lines, line)
			}
			file.Close()
		} else {
			lines, err = app.readLastNLines(path, app.InitialLines, app.lineDelim())
		}
	}

	if err != nil {
		region.List.AddItem(fmt.Sprintf("Error: %v", err), "", 0, nil)
		return
	}

	region.LinesMutex.Lock()
	region.Lines = lines
	region.LinesMutex.Unlock()

	// Update list directly; we're still before Run() so QueueUpdateDraw would deadlock.
	for _, line := range lines {
		region.List.AddItem(app.applyColorRules(line), "", 0, nil)
	}
	if app.followMode {
		region.List.SetCurrentItem(region.List.GetItemCount() - 1)
	}
}

// readLastNLines reads the last N lines (or NUL-delimited records) from a file.
func (app *App) readLastNLines(filename string, n int, delim byte) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf(ErrFileOpen, err)
	}
	defer file.Close()

	var lines []string
	var fileSize int64

	if stat, err := file.Stat(); err == nil {
		fileSize = stat.Size()
	} else {
		return nil, fmt.Errorf("Error getting file size: %v", err)
	}

	var offset int64 = fileSize
	var chunkSize int64 = 1024
	var buf []byte
	var lineBuffer []byte
	lineCount := 0

	for offset > 0 && lineCount <= n {
		if offset < chunkSize {
			chunkSize = offset
			offset = 0
		} else {
			offset -= chunkSize
		}

		buf = make([]byte, chunkSize)
		_, err := file.ReadAt(buf, offset)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("Error reading file: %v", err)
		}

		for i := len(buf) - 1; i >= 0; i-- {
			if buf[i] == delim {
				if len(lineBuffer) > 0 {
					lines = append([]string{string(lineBuffer)}, lines...)
					lineBuffer = nil
				}
				lineCount++
				if lineCount >= n {
					break
				}
			} else {
				lineBuffer = append([]byte{buf[i]}, lineBuffer...)
			}
		}
	}

	if len(lineBuffer) > 0 && lineCount < n {
		lines = append([]string{string(lineBuffer)}, lines...)
	}

	return lines, nil
}

// readLastNBytes reads the last n bytes from a file and splits into lines (by \n).
func (app *App) readLastNBytes(filename string, n int64) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf(ErrFileOpen, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	size := stat.Size()
	if n > size {
		n = size
	}
	if n <= 0 {
		return []string{}, nil
	}

	_, err = file.Seek(-n, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek: %w", err)
	}
	buf := make([]byte, n)
	read, err := io.ReadFull(file, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("read: %w", err)
	}
	buf = buf[:read]
	return bytesToLines(buf, app.lineDelim()), nil
}

// readFromByte reads from byte offset to EOF and splits into lines.
func (app *App) readFromByte(filename string, from int64) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf(ErrFileOpen, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if from >= stat.Size() {
		return []string{}, nil
	}

	_, err = file.Seek(from, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("seek: %w", err)
	}
	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return bytesToLines(buf, app.lineDelim()), nil
}

// bytesToLines splits data by the given delimiter (e.g. '\n' or '\x00').
func bytesToLines(data []byte, delim byte) []string {
	if len(data) == 0 {
		return nil
	}
	sep := string([]byte{delim})
	raw := strings.Split(string(data), sep)
	lines := make([]string, 0, len(raw))
	for _, s := range raw {
		if delim == '\n' {
			s = strings.TrimRight(s, "\r")
		}
		lines = append(lines, s)
	}
	return lines
}

// readFromLineN reads from line N (1-based) to end of file; skips first N-1 lines/records.
func (app *App) readFromLineN(filename string, n int, delim byte) ([]string, error) {
	if n < 1 {
		return nil, fmt.Errorf("lines-from must be >= 1")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf(ErrFileOpen, err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for i := 0; i < n-1; i++ {
		_, err := reader.ReadString(delim)
		if err != nil {
			if err == io.EOF {
				return []string{}, nil
			}
			return nil, fmt.Errorf("read: %w", err)
		}
	}

	var lines []string
	trimSuffix := "\r\n"
	if delim == '\x00' {
		trimSuffix = "\x00"
	}
	for {
		line, err := reader.ReadString(delim)
		if err != nil {
			if err == io.EOF {
				line = strings.TrimSuffix(line, trimSuffix)
				if line != "" {
					lines = append(lines, line)
				}
				break
			}
			return nil, fmt.Errorf("read: %w", err)
		}
		lines = append(lines, strings.TrimSuffix(line, trimSuffix))
	}
	return lines, nil
}

// setupHandlers sets up input handlers and event listeners
func (app *App) setupHandlers() {
	// ruleInput DoneFunc is set in initiateAddRule (search-style show/hide)
	app.tviewApp.SetInputCapture(app.handleGlobalInput)

	if app.messagesView != nil {
		app.messagesView.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
			app.selectedLineIndex = index
			app.updateProgressBar()
			app.updateHelpPane()
		})
		app.messagesView.SetSelectedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
			app.selectedLineIndex = index
			app.viewSelectedLine()
		})
	}
}

// clearPopup removes the current overlay popup (if any). Call after closing search/rule/text popup.
// Leaves focus on rootOverlay so its InputHandler keeps receiving keys and forwarding to the list.
func (app *App) clearPopup() {
	app.rootOverlay.ClearPopup()
	app.rootOverlay.SetEscapeHandler(nil)
	// Do not SetFocus(list): tview only calls root.InputHandler() when root.HasFocus(), so we must keep focus on the overlay.
}

// closeAddRuleInput closes the add-rule popup.
func (app *App) closeAddRuleInput() {
	app.clearPopup()
	app.currentFocus = focusMessages
}

// initiateAddRule shows a centered popup over the TUI (Enter = add, Esc = cancel). No buttons.
func (app *App) initiateAddRule() {
	logging.LogAppAction("Initiating add matching rule (popup)")
	app.ruleInput.SetText("")
	app.ruleInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			ruleText := strings.TrimSpace(app.ruleInput.GetText())
			app.closeAddRuleInput()
			if ruleText != "" {
				rule, err := rules.ParseRule(ruleText)
				if err != nil {
					app.showMessage(fmt.Sprintf("Error parsing rule: %v", err), app.rootOverlay)
					return
				}
				app.rules = append(app.rules, rule)
				app.updateRulesView()
			}
		} else if key == tcell.KeyEscape {
			app.closeAddRuleInput()
		}
	})
	// Popup width = half screen (overlay draws it centered); field fills inside minus label
	_, _, w, _ := app.rootOverlay.GetRect()
	if w <= 0 {
		w = 80
	}
	popupW := w / 2
	if popupW < 40 {
		popupW = 40
	}
	inner := popupW - 2 // left+right border
	labelLen := len("Add Matching Rule: ")
	fieldW := inner - labelLen
	if fieldW < 5 {
		fieldW = 5
	}
	app.ruleInput.SetFieldWidth(fieldW)
	popup := tview.NewGrid().SetRows(1).SetColumns(-1).AddItem(app.ruleInput, 0, 0, 1, 1, 0, 0, true)
	popup.SetBorder(true).SetBackgroundColor(tcell.NewRGBColor(30, 30, 30))
	app.rootOverlay.SetPopupWithFocus(popup, app.ruleInput, 3)
	app.tviewApp.SetFocus(app.rootOverlay)
	app.currentFocus = focusRuleInput
}

// cancelAddRule closes the add-rule input (from Escape in global handler).
func (app *App) cancelAddRule() {
	app.closeAddRuleInput()
}

// handleGlobalInput handles global key shortcuts
func (app *App) handleGlobalInput(event *tcell.EventKey) *tcell.EventKey {
	// Generic text popup (help, view line): only Esc closes (Enter does not)
	if app.textPopupOnClose != nil {
		if event.Key() == tcell.KeyEscape {
			app.textPopupOnClose()
			app.textPopupOnClose = nil
			return nil
		}
		return nil
	}
	// When in search or add-rule popup, only handle Tab/Backtab/Escape; pass everything else to the input
	if app.currentFocus == focusSearchInput || app.currentFocus == focusRuleInput {
		switch event.Key() {
		case tcell.KeyTab, tcell.KeyBacktab:
			return nil
		case tcell.KeyEscape:
			if app.currentFocus == focusSearchInput {
				app.cancelSearch()
			} else {
				app.cancelAddRule()
			}
			return nil
		default:
			return event // pass to input so user can type
		}
	}

	// Handle global shortcuts
	switch event.Key() {
	case tcell.KeyTab:
		forward := (event.Modifiers() & tcell.ModShift) == 0
		app.cycleFocus(forward)
		return nil
	case tcell.KeyBacktab:
		// Shift+Tab is often sent as KeyBacktab; cycle to previous pane (don't let list treat it as "move up")
		app.cycleFocus(false)
		return nil
	case tcell.KeyEscape:
		if app.tviewApp.GetFocus() == app.saveFilenameInput {
			app.cancelSave()
			return nil
		} else if app.currentFocus == focusSearchInput || app.currentFocus == focusRuleInput {
			if app.currentFocus == focusSearchInput {
				app.cancelSearch()
			} else {
				app.cancelAddRule()
			}
			return nil
		}
	case tcell.KeyRune:
		switch event.Rune() {
		case keyBindings["help"], '?':
			app.showHelp()
			return nil
		case keyBindings["quit"]:
			if app.textPopupOnClose != nil {
				return nil
			}
			if app.currentFocus != focusRuleInput && app.currentFocus != focusSearchInput && app.tviewApp.GetFocus() != app.saveFilenameInput {
				app.quit()
				return nil
			}
		}
	}

	// Handle pane-specific shortcuts
	currentFocus := app.currentFocus
	switch currentFocus {
	case focusMessages:
		switch event.Key() {
		case tcell.KeyEnter:
			app.viewSelectedLine()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case keyBindings["view"]:
				app.viewSelectedLine()
			case keyBindings["follow"]:
				app.toggleFollowMode()
			case keyBindings["search"]:
				app.initiateSearch()
			case keyBindings["next"]:
				app.nextSearchResult()
			case keyBindings["addRule"]:
				app.initiateAddRule()
			}
			return nil
		}
	case focusRulesView:
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
			case keyBindings["save"]:
				app.initiateSave()
			case keyBindings["delete"]:
				app.deleteSelectedRule()
				return nil
			case keyBindings["sensitive"]:
				app.toggleCaseSensitive()
				return nil
			case keyBindings["partial"]:
				app.togglePartialMatch()
				return nil
			case keyBindings["addRule"]:
				app.initiateAddRule()
			}
		}

	case focusViewModal:
		switch event.Key() {
		case tcell.KeyEnter, tcell.KeyEscape:
			app.closeViewModal()
			return nil
		}
	}

	return event
}

// closeSearchInput closes the search popup.
func (app *App) closeSearchInput() {
	app.clearPopup()
	app.currentFocus = focusMessages
}

// initiateSearch shows a centered popup over the TUI (Enter = search, Esc = cancel). No buttons.
func (app *App) initiateSearch() {
	logging.LogAppAction("Initiating search operation (popup)")
	app.searchInput.SetText("")
	app.searchInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			app.searchTerm = strings.TrimSpace(app.searchInput.GetText())
			app.closeSearchInput()
			if app.searchTerm != "" {
				app.performSearch()
				app.updateHelpPane()
			}
		} else if key == tcell.KeyEscape {
			app.cancelSearch()
		}
	})
	// Popup width = half screen (overlay draws it centered); field fills inside minus label
	_, _, w, _ := app.rootOverlay.GetRect()
	if w <= 0 {
		w = 80
	}
	popupW := w / 2
	if popupW < 40 {
		popupW = 40
	}
	inner := popupW - 2
	labelLen := len("Search: ")
	fieldW := inner - labelLen
	if fieldW < 5 {
		fieldW = 5
	}
	app.searchInput.SetFieldWidth(fieldW)
	popup := tview.NewGrid().SetRows(1).SetColumns(-1).AddItem(app.searchInput, 0, 0, 1, 1, 0, 0, true)
	popup.SetBorder(true).SetBackgroundColor(tcell.NewRGBColor(30, 30, 30))
	app.rootOverlay.SetPopupWithFocus(popup, app.searchInput, 3)
	app.tviewApp.SetFocus(app.rootOverlay)
	app.currentFocus = focusSearchInput
}

// performSearch searches through the messages for the search term
func (app *App) performSearch() {
	app.searchResults = []int{}
	app.currentSearchIndex = 0

	// Compile the regex
	regex, err := regexp.Compile(app.searchTerm)
	if err != nil {
		logging.LogAppAction(fmt.Sprintf("Invalid regex: %v", err))
		app.showMessage(fmt.Sprintf("Invalid regex: %v", err), app.rootOverlay)
		return
	}

	lv := app.currentMessagesView()
	if lv == nil {
		return
	}
	for i := 0; i < lv.GetItemCount(); i++ {
		mainText, _ := lv.GetItemText(i)
		if regex.MatchString(mainText) {
			app.searchResults = append(app.searchResults, i)
		}
	}

	if len(app.searchResults) == 0 {
		return // only jump when we have results; no extra message
	}

	app.currentSearchIndex = 0
	lv.SetCurrentItem(app.searchResults[app.currentSearchIndex])
	app.selectedLineIndex = app.searchResults[app.currentSearchIndex]
	app.updateProgressBar()
	app.updateHelpPane() // Update help pane to display search count
}

// nextSearchResult moves to the next search result
func (app *App) nextSearchResult() {
	if len(app.searchResults) == 0 {
		app.showMessage("No search in progress", app.rootOverlay)
		return
	}
	lv := app.currentMessagesView()
	if lv == nil {
		return
	}
	app.currentSearchIndex = (app.currentSearchIndex + 1) % len(app.searchResults)
	lv.SetCurrentItem(app.searchResults[app.currentSearchIndex])
	app.selectedLineIndex = app.searchResults[app.currentSearchIndex]
	app.updateProgressBar()
	app.updateHelpPane()
}

// cancelSearch removes the search input row and clears search state (no root change).
func (app *App) cancelSearch() {
	app.closeSearchInput()
	app.searchTerm = ""
	app.searchResults = nil
	app.currentSearchIndex = 0
	app.updateHelpPane()
}

// toggleFollowMode toggles the follow mode on or off
func (app *App) toggleFollowMode() {
	app.followMode = !app.followMode
	if app.followMode && !app.tailStarted && !app.FullMode {
		app.tailStarted = true
		if app.ZeroTerminated {
			go app.tailInputMessagesFileZeroTerminated(app.runCtx)
		} else {
			go app.tailInputMessagesFile(app.runCtx)
		}
	}
	app.updateMessagesPaneTitle()
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

// cycleFocus cycles the UI focus between panes. Tab = forward, Shift+Tab = backward.
// Order: file lists (0..N-1), rules view — then wrap to first file (rule input and search are not in Tab cycle).
func (app *App) cycleFocus(forward bool) {
	nRegions := len(app.fileRegions)
	messageSlots := 1
	if nRegions > 0 {
		messageSlots = nRegions
	}
	totalSlots := messageSlots + 1 // files, rules view only (rule input and search are show-on-shortcut)

	slot := 0
	switch app.currentFocus {
	case focusMessages:
		if nRegions > 0 {
			slot = app.focusedRegionIndex
		} else {
			slot = 0
		}
	case focusRulesView:
		slot = messageSlots
	case focusRuleInput, focusSearchInput:
		// From rule/search input, "next" wraps to first file
		slot = messageSlots
	default:
		slot = 0
	}

	var targetSlot int
	if forward {
		targetSlot = (slot + 1) % totalSlots
	} else {
		targetSlot = (slot - 1 + totalSlots) % totalSlots
	}

	if targetSlot < messageSlots {
		app.currentFocus = focusMessages
		app.focusedRegionIndex = targetSlot
		list := app.fileRegions[targetSlot].List
		app.selectedLineIndex = list.GetCurrentItem()
		app.updateProgressBar()
		app.updateHelpPane()
	}
	if targetSlot >= messageSlots {
		app.currentFocus = focusRulesView
	}
	app.tviewApp.SetFocus(app.rootOverlay)
	logging.LogAppAction(fmt.Sprintf("Focus cycled to slot %d", targetSlot))
}

// viewSelectedLine displays the selected line in the same overlay popup style as Help/Search.
func (app *App) viewSelectedLine() {
	lv := app.currentMessagesView()
	if lv == nil || app.currentFocus != focusMessages || app.selectedLineIndex >= lv.GetItemCount() {
		return
	}
	mainText, _ := lv.GetItemText(app.selectedLineIndex)
	body := fmt.Sprintf("[white]%s[-]", mainText)
	app.showTextPopup("View Line", body, 5, func() { // 5 lines so wrapped text has room
		app.clearPopup()
		app.textPopupOnClose = nil
	})
	logging.LogAppAction(fmt.Sprintf("Viewed selected line: %d", app.selectedLineIndex))
}

// closeViewModal closes the text popup if open (Esc handling).
func (app *App) closeViewModal() {
	if app.textPopupOnClose != nil {
		app.textPopupOnClose()
		app.textPopupOnClose = nil
	}
	app.clearPopup()
	app.tviewApp.SetFocus(app.rootOverlay)
	app.currentFocus = focusMessages
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
	app.currentFocus = focusSaveInput
}

// handleSaveInput handles the saving of log content to a file
func (app *App) handleSaveInput() {
	filename := app.saveFilenameInput.GetText()
	app.flex.RemoveItem(app.saveFilenameInput)
	if strings.TrimSpace(filename) == "" {
		logging.LogAppAction(MsgFilenameEmpty)
		app.showMessage(MsgFilenameEmpty, app.rootOverlay)
		app.tviewApp.SetFocus(app.rootOverlay)
		app.currentFocus = focusMessages
		return
	}

	var err error

	logging.LogAppAction(fmt.Sprintf("appfocus: %v", app.currentFocus))
	switch app.currentFocus {
	case focusMessages:
		var contentToSave []string
		if app.FullMode {
			contentToSave, err = app.getFullContent()
			if err != nil {
				logging.LogAppAction(fmt.Sprintf("Error getting full content: %v", err))
				app.showMessage(fmt.Sprintf("Error getting full content: %v", err), app.rootOverlay)
				return
			}
		} else {
			lines, mutex := app.currentLinesAndMutex()
			mutex.Lock()
			contentToSave = append([]string{}, *lines...)
			mutex.Unlock()
		}
		err = app.saveToFile(filename, contentToSave)
	case focusRulesView, focusSaveInput:
		err = app.saveRulesToFile(filename, app.rules)
	case focusViewModal:
		contentToSave := []string{app.viewModal.GetText(true)}
		err = app.saveToFile(filename, contentToSave)
	default:
		logging.LogAppAction(MsgInvalidContext)
		app.showMessage(MsgInvalidContext, app.rootOverlay)
		return
	}

	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileWrite, err))
		app.showMessage(fmt.Sprintf(ErrFileWrite, err), app.rootOverlay)
	} else {
		logging.LogAppAction(fmt.Sprintf(MsgFileSaved, filename))
		app.showMessage(fmt.Sprintf(MsgFileSaved, filename), app.rootOverlay)
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

// cancelSave cancels the save operation and returns focus to the overlay (arrow keys work again).
func (app *App) cancelSave() {
	app.flex.RemoveItem(app.saveFilenameInput)
	app.tviewApp.SetFocus(app.rootOverlay)
	app.currentFocus = focusMessages
}

// deleteSelected deletes the selected line or rule
func (app *App) deleteSelected() {
	lv := app.currentMessagesView()
	if lv != nil && app.currentFocus == focusMessages && app.selectedLineIndex < lv.GetItemCount() {
		lv.RemoveItem(app.selectedLineIndex)
		if app.FullMode {
			app.showMessage("Deletion not supported in full mode", app.rootOverlay)
		} else {
			lines, mutex := app.currentLinesAndMutex()
			mutex.Lock()
			defer mutex.Unlock()
			if app.selectedLineIndex < len(*lines) {
				*lines = append((*lines)[:app.selectedLineIndex], (*lines)[app.selectedLineIndex+1:]...)
			}
		}
		app.updateProgressBar()
		app.updateHelpPane()
	} else if app.currentFocus == focusRulesView && app.selectedRuleIndex < len(app.rules) {
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

// drawHeaderLine draws full-width header: ────| Title |──── (4 dashes left, title block, fill right).
// active=true uses ═ and titleGreen colours only the title text green (for active file).
func drawHeaderLine(screen tcell.Screen, x, y, width int, title string, active bool, titleGreen bool) {
	if width <= 0 {
		return
	}
	bg := tview.Styles.PrimitiveBackgroundColor
	lineCh := rune(0x2500) // ─
	if active {
		lineCh = rune(0x2550) // ═
	}
	lineStyle := tcell.StyleDefault.Foreground(tview.Styles.BorderColor).Background(bg)
	titleCol := tview.Styles.TitleColor
	if titleGreen {
		titleCol = tcell.ColorGreen
	}
	px := x
	for i := 0; i < 4 && px < x+width; i++ {
		screen.SetContent(px, y, lineCh, nil, lineStyle)
		px++
	}
	for _, r := range "| " {
		if px < x+width {
			screen.SetContent(px, y, r, nil, lineStyle)
			px++
		}
	}
	titleStart := px
	tview.Print(screen, title, titleStart, y, width-(titleStart-x)-3, tview.AlignLeft, titleCol)
	px = titleStart + len([]rune(title))
	for _, r := range " |" {
		if px < x+width {
			screen.SetContent(px, y, r, nil, lineStyle)
			px++
		}
	}
	for px < x+width {
		screen.SetContent(px, y, lineCh, nil, lineStyle)
		px++
	}
}

// initUI initializes the UI components and layout.
// Same header+list layout for 1 or N files: ────| path |──── full width; active file uses ═ and green filename.
func (app *App) initUI() {
	app.multiFileView = tview.NewFlex().SetDirection(tview.FlexRow)
	for i, path := range app.inputFiles {
		idx := i
		header := tview.NewTextView()
		header.SetBorder(false)
		header.SetDynamicColors(false)
		header.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
			if width <= 0 || height <= 0 {
				return x, y, width, height
			}
			// Only highlight when focus is actually on a file list (messages pane), not when on rule input etc.
			selected := app.currentFocus == focusMessages && len(app.fileRegions) > 0 && app.focusedRegionIndex == idx
			drawHeaderLine(screen, x, y, width, path, selected, selected)
			return x, y + 1, width, 0
		})

		list := tview.NewList()
		list.ShowSecondaryText(false)
		list.SetBorder(false)
		region := &FileRegion{Path: path, Header: header, List: list, Lines: []string{}}
		app.fileRegions = append(app.fileRegions, region)

		regionFlex := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(header, 1, 0, false).
			AddItem(list, 0, 1, false)
		app.multiFileView.AddItem(regionFlex, 0, 1, false)

		list.SetFocusFunc(func() {
			app.focusedRegionIndex = idx
			app.currentFocus = focusMessages
			app.selectedLineIndex = list.GetCurrentItem()
			app.updateProgressBar()
			app.updateHelpPane()
		})
		list.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
			app.focusedRegionIndex = idx
			app.currentFocus = focusMessages
			app.selectedLineIndex = index
			app.updateProgressBar()
			app.updateHelpPane()
		})
		list.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
			app.focusedRegionIndex = idx
			app.currentFocus = focusMessages
			app.selectedLineIndex = index
			app.viewSelectedLine()
		})
	}
	app.focusedRegionIndex = 0

	// Initialize rulesView with same header format: ────| Matching Rules |────
	app.rulesView = tview.NewTextView()
	app.rulesView.SetDynamicColors(true)
	app.rulesView.SetBorder(false)
	rulesHeader := tview.NewTextView()
	rulesHeader.SetBorder(false)
	rulesHeader.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		if width > 0 && height > 0 {
			selected := app.currentFocus == focusRulesView
			drawHeaderLine(screen, x, y, width, "Matching Rules", selected, selected)
		}
		return x, y + 1, width, 0
	})
	rulesContainer := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(rulesHeader, 1, 0, false).
		AddItem(app.rulesView, 0, 1, false)

	app.rulesView.SetFocusFunc(func() {
		app.currentFocus = focusRulesView
	})

	// Initialize ruleInput
	app.ruleInput = tview.NewInputField()
	app.ruleInput.SetLabel("Add Matching Rule: ")
	app.ruleInput.SetFieldWidth(30)
	app.ruleInput.SetFocusFunc(func() {
		app.currentFocus = focusRuleInput
	})

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

	// Initialize searchInput
	app.searchInput = tview.NewInputField()
	app.searchInput.SetLabel("Search: ")
	app.searchInput.SetFieldWidth(30)
	app.searchInput.SetFocusFunc(func() {
		app.currentFocus = focusSearchInput
	})

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

	// Create a top FlexRow containing messages area and rulesView side by side
	topFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(app.multiFileView, 0, 8, false)

	// Initialize the main Flex layout with topFlex and other components stacked vertically
	// ruleInput and searchInput are shown as popups on 'r' and '/', not in the layout
	app.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(topFlex, 0, 8, false).
		AddItem(rulesContainer, 0, 2, false).
		AddItem(app.saveFilenameInput, 0, 0, false). // Initially hidden
		AddItem(app.progressBar, 1, 0, false).
		AddItem(app.helpText, 1, 0, false)          // Existing help pane

	// Root is overlay: flex full-screen, popup (when shown) centered at half screen width; TUI stays visible.
	app.rootOverlay = newOverlayRoot(app.flex)
	app.rootOverlay.SetGetFocus(func() tview.Primitive {
		if l := app.currentMessagesView(); l != nil {
			return l
		}
		if app.currentFocus == focusRulesView {
			return app.rulesView
		}
		return app.flex
	})
	app.tviewApp.SetRoot(app.rootOverlay, true)
	// Keep focus on the overlay so tview calls overlay.InputHandler(); we forward to list via getFocus().
	app.tviewApp.SetFocus(app.rootOverlay)
	if app.currentMessagesView() != nil && len(app.fileRegions) > 0 {
		app.focusedRegionIndex = 0
		app.selectedLineIndex = app.fileRegions[0].List.GetCurrentItem()
		app.updateProgressBar()
		app.updateHelpPane()
	}
	app.currentFocus = focusMessages
}

// showTextPopup shows a generic overlay popup (same style as Search/Add Rule): title, text body,
// dark background for frame and content. Only Esc closes. height in rows (0 = default 18).
func (app *App) showTextPopup(title, body string, height int, onClose func()) {
	darkGray := tcell.NewRGBColor(30, 30, 30)
	tv := tview.NewTextView()
	tv.SetText("[white]" + body + "[-]")
	tv.SetDynamicColors(true)
	tv.SetWordWrap(true)
	tv.SetBackgroundColor(darkGray)
	popup := tview.NewGrid().SetRows(-1).SetColumns(-1).AddItem(tv, 0, 0, 1, 1, 0, 0, false)
	popup.SetBorder(true).SetTitle(" " + title + " ").SetBackgroundColor(darkGray)
	if height <= 0 {
		height = 18
	}
	app.rootOverlay.SetTextPopup(popup, height)
	app.textPopupOnClose = onClose
	app.rootOverlay.SetEscapeHandler(func() {
		if app.textPopupOnClose != nil {
			app.textPopupOnClose()
			app.textPopupOnClose = nil
		}
	})
	app.tviewApp.SetFocus(app.rootOverlay)
}

// showHelp displays the help popup (same overlay style as Search/Add Rule).
func (app *App) showHelp() {
	helpContent := `
Keybindings:
- Tab: Cycle focus
- Up/Down: Navigate
- Enter/v: View selected line
- s: Save
- d: Delete selected
- f: Toggle follow mode
- /: Search
- n: Next search result
- r: Add matching rule
- q: Quit
- h, ?: Show this help
`
	app.showTextPopup("Help", helpContent, 18, func() {
		app.clearPopup()
		app.textPopupOnClose = nil
	})
}

// showMessage displays a modal with the given message (used for errors etc.)
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

// tailInputMessagesFileZeroTerminated follows a file with NUL-delimited records (tail -z -f).
// The standard tail library only supports newline; this custom loop polls and reads by \x00.
func (app *App) tailInputMessagesFileZeroTerminated(ctx context.Context) {
	logging.LogAppAction("Starting to tail input messages file (zero-terminated)")
	file, err := os.Open(app.inputMessagesFile)
	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileOpen, err))
		log.Fatalf(ErrFileOpen, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		logging.LogAppAction(fmt.Sprintf("Stat: %v", err))
		return
	}
	pos := stat.Size()

	sleepDur := 250 * time.Millisecond
	if app.SleepInterval > 0 {
		sleepDur = time.Duration(app.SleepInterval * float64(time.Second))
	}

	var recordBuf []byte
	readBuf := make([]byte, 65536)

	for {
		select {
		case <-ctx.Done():
			logging.LogAppAction("Tail (zero-term) goroutine exiting")
			return
		default:
		}

		stat, err := file.Stat()
		if err != nil {
			time.Sleep(sleepDur)
			continue
		}
		size := stat.Size()
		if size < pos {
			pos = size
		}
		if size > pos {
			_, err := file.Seek(pos, io.SeekStart)
			if err != nil {
				time.Sleep(sleepDur)
				continue
			}
			toRead := size - pos
			if toRead > int64(len(readBuf)) {
				toRead = int64(len(readBuf))
			}
			n, err := file.Read(readBuf[:toRead])
			if err != nil && err != io.EOF {
				time.Sleep(sleepDur)
				continue
			}
			if n > 0 {
				pos += int64(n)
				recordBuf = append(recordBuf, readBuf[:n]...)
				for {
					i := 0
					for i < len(recordBuf) && recordBuf[i] != '\x00' {
						i++
					}
					if i >= len(recordBuf) {
						break
					}
					record := string(recordBuf[:i])
					recordBuf = recordBuf[i+1:]
					if len(app.rules) == 0 || rules.MatchesAnyRule(record, app.rules) {
						app.addLine(record)
						app.tviewApp.QueueUpdateDraw(func() {
							app.messagesView.AddItem(app.applyColorRules(record), "", 0, nil)
							app.updateProgressBar()
							app.updateHelpPane()
							if app.followMode {
								app.messagesView.SetCurrentItem(app.messagesView.GetItemCount() - 1)
							}
						})
					}
				}
			}
		}

		time.Sleep(sleepDur)
	}
}

// tailInputMessagesFile tails the input messages file in normal mode.
// ReOpen is true only when -F (follow-name) is set; otherwise follow by descriptor (GNU tail -f).
func (app *App) tailInputMessagesFile(ctx context.Context) {
	logging.LogAppAction("Starting to tail input messages file")
	if app.SleepInterval > 0 {
		watch.POLL_DURATION = time.Duration(app.SleepInterval * float64(time.Second))
	}
	t, err := tail.TailFile(app.inputMessagesFile, tail.Config{
		Follow:    true,
		ReOpen:    app.FollowName, // true only with -F (follow by name, reopen on rotate)
		MustExist: !app.Retry,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		Poll:      true,
		Logger:    tail.DiscardingLogger,
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

					// Scroll to end if followMode is on
					if app.followMode {
						app.messagesView.SetCurrentItem(app.messagesView.GetItemCount() - 1)
					}
				})
			}
		}
	}
}

// addLine adds a line to the buffer in normal mode (single-file).
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

// addLineToRegion adds a line to a file region's buffer (multi-file).
func (app *App) addLineToRegion(region *FileRegion, line string) {
	region.LinesMutex.Lock()
	defer region.LinesMutex.Unlock()
	region.Lines = append(region.Lines, line)
	if len(region.Lines) > app.MaxLines {
		region.Lines = region.Lines[len(region.Lines)-app.MaxLines:]
	}
}

// tailInputMessagesFileForRegion tails one file and updates the given region (multi-file mode).
func (app *App) tailInputMessagesFileForRegion(ctx context.Context, region *FileRegion) {
	path := region.Path
	logging.LogAppAction("Starting to tail file (multi): " + path)
	if app.SleepInterval > 0 {
		watch.POLL_DURATION = time.Duration(app.SleepInterval * float64(time.Second))
	}
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    app.FollowName,
		MustExist: !app.Retry,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		Poll:      true,
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		logging.LogAppAction(fmt.Sprintf(ErrFileOpen, err))
		app.tviewApp.QueueUpdateDraw(func() {
			region.List.AddItem(fmt.Sprintf(ErrFileOpen, err), "", 0, nil)
		})
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-t.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				continue
			}
			if len(app.rules) == 0 || rules.MatchesAnyRule(line.Text, app.rules) {
				app.addLineToRegion(region, line.Text)
				app.tviewApp.QueueUpdateDraw(func() {
					region.List.AddItem(app.applyColorRules(line.Text), "", 0, nil)
					if region.List.GetItemCount() > app.MaxLines {
						region.List.RemoveItem(0)
					}
					app.updateProgressBar()
					app.updateHelpPane()
					if app.followMode {
						region.List.SetCurrentItem(region.List.GetItemCount() - 1)
					}
				})
			}
		}
	}
}

// tailInputMessagesFileZeroTerminatedForRegion tails one file with NUL delimiter and updates the region (multi-file).
func (app *App) tailInputMessagesFileZeroTerminatedForRegion(ctx context.Context, region *FileRegion) {
	path := region.Path
	logging.LogAppAction("Starting to tail file (multi, zero-term): " + path)
	sleepDur := 100 * time.Millisecond
	if app.SleepInterval > 0 {
		sleepDur = time.Duration(app.SleepInterval * float64(time.Second))
	}

	file, err := os.Open(path)
	if err != nil {
		app.tviewApp.QueueUpdateDraw(func() {
			region.List.AddItem(fmt.Sprintf(ErrFileOpen, err), "", 0, nil)
		})
		return
	}
	defer file.Close()

	stat, _ := file.Stat()
	pos := stat.Size()
	readBuf := make([]byte, 4096)
	var recordBuf []byte

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		stat, err := file.Stat()
		if err != nil {
			time.Sleep(sleepDur)
			continue
		}
		size := stat.Size()
		if size < pos {
			pos = size
		}
		if size > pos {
			_, _ = file.Seek(pos, io.SeekStart)
			toRead := size - pos
			if toRead > int64(len(readBuf)) {
				toRead = int64(len(readBuf))
			}
			n, err := file.Read(readBuf[:toRead])
			if err != nil && err != io.EOF {
				time.Sleep(sleepDur)
				continue
			}
			if n > 0 {
				pos += int64(n)
				recordBuf = append(recordBuf, readBuf[:n]...)
				for {
					i := 0
					for i < len(recordBuf) && recordBuf[i] != '\x00' {
						i++
					}
					if i >= len(recordBuf) {
						break
					}
					record := string(recordBuf[:i])
					recordBuf = recordBuf[i+1:]
					if len(app.rules) == 0 || rules.MatchesAnyRule(record, app.rules) {
						app.addLineToRegion(region, record)
						app.tviewApp.QueueUpdateDraw(func() {
							region.List.AddItem(app.applyColorRules(record), "", 0, nil)
							if region.List.GetItemCount() > app.MaxLines {
								region.List.RemoveItem(0)
							}
							app.updateProgressBar()
							app.updateHelpPane()
							if app.followMode {
								region.List.SetCurrentItem(region.List.GetItemCount() - 1)
							}
						})
					}
				}
			}
		}
		time.Sleep(sleepDur)
	}
}

// updateMessagesView refreshes the messagesView with the current lines
func (app *App) updateMessagesView() {
	lv := app.currentMessagesView()
	if lv == nil {
		return
	}
	lines, mutex := app.currentLinesAndMutex()
	mutex.Lock()
	ln := append([]string{}, *lines...)
	mutex.Unlock()
	lv.Clear()
	for _, line := range ln {
		lv.AddItem(app.applyColorRules(line), "", 0, nil)
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

	lines, mutex := app.currentLinesAndMutex()
	mutex.Lock()
	if app.FullMode {
		if r := app.currentRegion(); r != nil {
			totalLines = r.TotalLinesInFile
		} else {
			totalLines = len(*lines)
		}
	} else {
		totalLines = len(*lines)
	}
	currentIndex := app.selectedLineIndex + 1
	mutex.Unlock()

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

	lines, mutex := app.currentLinesAndMutex()
	mutex.Lock()
	if app.FullMode {
		if r := app.currentRegion(); r != nil {
			totalLines = r.TotalLinesInFile
		} else {
			totalLines = len(*lines)
		}
		offset := totalLines - len(*lines)
		currentLine = offset + app.selectedLineIndex + 1
	} else {
		totalLines = len(*lines)
		currentLine = app.selectedLineIndex + 1
	}
	mutex.Unlock()

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

	// If a search is active, show the match count
	if len(app.searchResults) > 0 {
		searchStatus := fmt.Sprintf(" | Matches: %d", len(app.searchResults))
		helpMessage += lineStatus + searchStatus
	} else {
		helpMessage += lineStatus
	}

	app.helpText.SetText(helpMessage)
}

// getFullContent reads the entire file content for saving in full mode
func (app *App) getFullContent() ([]string, error) {
	path := app.inputMessagesFile
	if r := app.currentRegion(); r != nil {
		path = r.Path
	}
	file, err := os.Open(path)
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
