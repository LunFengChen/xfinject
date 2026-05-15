package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/muesli/termenv"
)

var (
	logger *log.Logger
	styles *log.Styles
)

// Catppuccin Mocha palette
const (
	colOverlay0 = "#6c7086" // dim gray      — debug level, separators
	colSurface2 = "#585b70" // darker gray   — keys
	colText     = "#cdd6f4" // base text
	colSapphire = "#74c7ec" // info level
	colYellow   = "#f9e2af" // warn level, paths, files
	colRed      = "#f38ba8" // error level
	colPeach    = "#fab387" // addresses / hex values
	colMauve    = "#cba6f7" // numeric counts, pids
	colBlue     = "#89b4fa" // type/mode/flag values
	colGreen    = "#a6e3a1" // symbol names, packages
	colLavender = "#b4befe" // generic values
	colTeal     = "#94e2d5" // handles / results
)

func init() {
	lipgloss.SetColorProfile(termenv.TrueColor)

	styles = log.DefaultStyles()

	// Level prefixes — bracket symbols, plain ASCII
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("[?]").
		Foreground(lipgloss.Color(colOverlay0))
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("[+]").
		Foreground(lipgloss.Color(colSapphire))
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("[!]").
		Foreground(lipgloss.Color(colYellow))
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("[x]").
		Foreground(lipgloss.Color(colRed))

	// Message text
	styles.Message = lipgloss.NewStyle().Foreground(lipgloss.Color(colText))

	// Key/value base styles
	styles.Key = lipgloss.NewStyle().Foreground(lipgloss.Color(colSurface2))
	styles.Value = lipgloss.NewStyle().Foreground(lipgloss.Color(colLavender))

	// --- Per-key value coloring ---

	// Addresses / hex (peach)
	hexStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colPeach)).
		Transform(func(s string) string {
			if num, err := strconv.ParseUint(s, 0, 64); err == nil {
				return fmt.Sprintf("0x%x", num)
			}
			return s
		})
	for _, k := range []string{
		"addr", "mmap_addr", "hook_addr", "marker_addr", "dlopen_addr",
		"mmap_region", "handle", "base", "from", "to", "start", "end",
		"vaddr", "paddr", "offset", "final_va", "target_pc", "svc_pc",
		"mailbox", "child_mailbox", "uds_path", "fd", "socket_path",
	} {
		styles.Values[k] = hexStyle
	}

	// Numeric counts / pids (mauve)
	numStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colMauve))
	for _, k := range []string{
		"pid", "size", "count", "attempt", "timeout", "child_pid",
		"idx", "total", "score", "critical", "high", "medium", "low",
	} {
		styles.Values[k] = numStyle
	}

	// Symbol / name identifiers (green)
	symStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colGreen))
	for _, k := range []string{
		"symbol", "hook_func", "marker_var", "name", "sym", "lib",
		"section", "tag", "sentinel", "package", "cmdline", "activity",
	} {
		styles.Values[k] = symStyle
	}

	// Paths / files (yellow)
	pathStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colYellow))
	for _, k := range []string{
		"path", "payload", "file", "target", "outpath", "runpath",
	} {
		styles.Values[k] = pathStyle
	}

	// Modes / types / flags (blue bold)
	typeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colBlue)).Bold(true)
	for _, k := range []string{
		"type", "mode", "flags", "level", "bind", "severity", "risk",
	} {
		styles.Values[k] = typeStyle
	}

	// Results / handles (teal)
	for _, k := range []string{"result", "hook_func_resolved", "msg"} {
		styles.Values[k] = lipgloss.NewStyle().Foreground(lipgloss.Color(colTeal))
	}
	// Errors (red)
	for _, k := range []string{"error", "reason"} {
		styles.Values[k] = lipgloss.NewStyle().Foreground(lipgloss.Color(colRed))
	}

	logger = log.NewWithOptions(os.Stdout, log.Options{
		ReportTimestamp: false,
		ReportCaller:    false,
	})
	logger.SetStyles(styles)
	logger.SetColorProfile(termenv.TrueColor)
	logger.SetLevel(log.InfoLevel)
}

func LogDebug(msg string, kv ...any) { logger.Debug(msg, kv...) }
func LogInfo(msg string, kv ...any)  { logger.Info(msg, kv...) }
func LogWarn(msg string, kv ...any)  { logger.Warn(msg, kv...) }
func LogError(msg string, kv ...any) { logger.Error(msg, kv...) }

func SetLogLevel(level string) error {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "info", "":
		logger.SetLevel(log.InfoLevel)
	case "warn", "warning":
		logger.SetLevel(log.WarnLevel)
	case "error":
		logger.SetLevel(log.ErrorLevel)
	default:
		return fmt.Errorf("unknown log level: %s", level)
	}
	return nil
}
