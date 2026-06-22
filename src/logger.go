package xfinject

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/muesli/termenv"
)

var logger *log.Logger

// Catppuccin Mocha palette
const (
	colOverlay0 = "#6c7086" // debug level, keys
	colSapphire = "#74c7ec" // info level
	colYellow   = "#f9e2af" // warn level, paths
	colRed      = "#f38ba8" // error level, errors
	colPeach    = "#fab387" // hex / addresses
	colMauve    = "#cba6f7" // counts, pids
	colBlue     = "#89b4fa" // types, modes, flags
	colGreen    = "#a6e3a1" // names, symbols, packages
	colLavender = "#b4befe" // default values
	colText     = "#cdd6f4" // message text
)

func init() {
	lipgloss.SetColorProfile(termenv.TrueColor)

	styles := log.DefaultStyles()
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().SetString("[?]").Foreground(lipgloss.Color(colOverlay0))
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().SetString("[+]").Foreground(lipgloss.Color(colSapphire))
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().SetString("[!]").Foreground(lipgloss.Color(colYellow))
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().SetString("[x]").Foreground(lipgloss.Color(colRed))
	styles.Message = lipgloss.NewStyle().Foreground(lipgloss.Color(colText))
	styles.Key = lipgloss.NewStyle().Foreground(lipgloss.Color(colOverlay0))
	styles.Value = lipgloss.NewStyle().Foreground(lipgloss.Color(colLavender))

	// Addresses / hex values rendered as 0x%x.
	hexStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colPeach)).
		Transform(func(s string) string {
			if n, err := strconv.ParseUint(s, 0, 64); err == nil {
				return "0x" + strconv.FormatUint(n, 16)
			}
			return s
		})
	for _, k := range []string{
		"addr", "base", "end", "handle", "mailbox", "mailbox_off", "offset", "slot", "start", "stage_base", "stage_end", "value",
	} {
		styles.Values[k] = hexStyle
	}

	// Numeric counts / pids.
	numStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colMauve))
	for _, k := range []string{
		"api", "candidates", "child_pid", "count", "elapsed_ms", "index", "iterations", "payloads", "pid", "size", "timeout_ms", "uid", "zygote_pid",
	} {
		styles.Values[k] = numStyle
	}

	// Names / symbols / packages.
	symStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colGreen))
	for _, k := range []string{
		"activity", "lib", "package", "symbol", "tag", "tags",
	} {
		styles.Values[k] = symStyle
	}

	// Paths / files.
	pathStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colYellow))
	for _, k := range []string{
		"path", "payload", "stage_path",
	} {
		styles.Values[k] = pathStyle
	}

	// Types / modes / flags (bold blue).
	typeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colBlue)).Bold(true)
	for _, k := range []string{
		"flags", "level", "mode", "perms", "type",
	} {
		styles.Values[k] = typeStyle
	}

	// Errors.
	errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colRed))
	for _, k := range []string{"error", "reason"} {
		styles.Values[k] = errStyle
	}

	logger = log.NewWithOptions(os.Stdout, log.Options{
		ReportTimestamp: false,
		ReportCaller:    false,
	})
	logger.SetStyles(styles)
	logger.SetColorProfile(termenv.TrueColor)
	logger.SetLevel(log.InfoLevel)
}

// SetLogLevel maps a string ("debug" | "info" | "warn" | "error") to the
// underlying log level. Empty string keeps the default (info).
func SetLogLevel(level string) error {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "":
		return nil
	case "debug":
		logger.SetLevel(log.DebugLevel)
	case "info":
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
