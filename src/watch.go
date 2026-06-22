package xfinject

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type WatchOptions struct {
	AllowlistPath string
	Interval      time.Duration
	PayloadID     string
	VmaHide       string
	Debug         bool
}

type processInfo struct {
	PID       int
	Package   string
	StartTime uint64
}

func RunWatch(opts WatchOptions) error {
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.PayloadID == "" {
		opts.PayloadID = "jnilog"
	}
	if opts.VmaHide == "" {
		opts.VmaHide = "auto"
	}
	if opts.Debug {
		_ = SetLogLevel("debug")
	}

	// Do not inject from the watcher.
	//
	// The first implementation tried to retrofit persistent jnilog by watching
	// enabled packages and calling Run(... ForceStop:true) once a process was
	// seen. That made a manually opened app get killed and relaunched, which is
	// a bad UX and also changes the app lifecycle under test.
	//
	// Persistent jnilog is now handled by the ROM zygote startup path. Keep this
	// command as a harmless diagnostic watcher so accidentally starting
	// xfinject_watchd can never close/reopen user apps again.
	logger.Info("xfinject watch start disabled-injector mode",
		"interval_ms", opts.Interval.Milliseconds(), "payload", opts.PayloadID)
	for {
		enabled, err := enabledJniLogPackages()
		if err != nil {
			logger.Warn("watch read enabled packages failed", "error", err)
			time.Sleep(opts.Interval)
			continue
		}
		pkgs := make([]string, 0, len(enabled))
		for pkg := range enabled {
			pkgs = append(pkgs, pkg)
		}
		sort.Strings(pkgs)
		if len(pkgs) > 0 {
			logger.Info("watch observed enabled jnilog packages; injection is handled by zygote",
				"packages", strings.Join(pkgs, ","))
		}
		time.Sleep(opts.Interval)
	}
}

func enabledJniLogPackages() (map[string]bool, error) {
	out, err := exec.Command("getprop").Output()
	if err != nil {
		return nil, err
	}
	enabled := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	const prefix = "[persist.rommgr.app."
	const suffix = ".jnilog_trace]"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, prefix) || !strings.Contains(line, suffix+":") {
			continue
		}
		end := strings.Index(line, suffix)
		if end <= len(prefix) {
			continue
		}
		pkg := line[len(prefix):end]
		if strings.HasSuffix(line, ": [1]") || strings.HasSuffix(line, ": [true]") {
			enabled[pkg] = true
		}
	}
	return enabled, scanner.Err()
}

func runningMainProcesses(enabled map[string]bool) map[string]processInfo {
	result := map[string]processInfo{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(cmdline) == 0 {
			continue
		}
		argv0, _, _ := bytes.Cut(cmdline, []byte{0})
		pkg := string(argv0)
		if !enabled[pkg] {
			continue
		}
		st, ok := procStartTime(pid)
		if !ok {
			continue
		}
		result[pkg] = processInfo{PID: pid, Package: pkg, StartTime: st}
	}
	return result
}

func pruneInjected(injected map[string]uint64, live map[string]processInfo) {
	for pkg := range injected {
		if live == nil {
			delete(injected, pkg)
			continue
		}
		if p, ok := live[pkg]; !ok || p.StartTime != injected[pkg] {
			delete(injected, pkg)
		}
	}
}
