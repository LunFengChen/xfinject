package xfinject

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ppidOf returns the parent pid from /proc/<pid>/stat. The comm field is
// (...)-quoted and may itself contain spaces or parens, so PPid is the second
// whitespace field after the LAST ')'.
func ppidOf(pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return 0, false
	}
	fields := bytes.Fields(data[i+1:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0, false
	}
	return ppid, true
}

// procStartTime returns the process start time (jiffies since boot) from
// /proc/<pid>/stat field 22. Like ppidOf, it parses from the LAST ')' so a
// comm containing spaces/parens can't shift the field offsets. Pairing the
// start time with the pid distinguishes the original process from a different
// one the kernel may have assigned the same pid after it exited — so a liveness
// poll can't be fooled by pid reuse.
func procStartTime(pid int) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return 0, false
	}
	fields := bytes.Fields(data[i+1:])
	if len(fields) < 20 {
		return 0, false
	}
	startTime, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0, false
	}
	return startTime, true
}

// FindProcessPid scans /proc for the canonical top-level process whose
// cmdline argv[0] equals `processName` EXACTLY and whose parent is init
// (PPid == 1).
//
// argv[0], NOT comm, is the discriminator: the zygote is app_process, so its
// /proc/<pid>/comm is "main" — shared by zygote64, the 32-bit zygote, and every
// freshly forked app. The "zygote64" / "zygote" name only appears in cmdline
// (set via setArgV0). So:
//   - Exact argv[0] match keeps zygote64 distinct from the 32-bit `zygote`,
//     `webview_zygote`, etc. They fork different-ABI children; trapping the
//     wrong one means our arm64 target never hits the trap and detection times
//     out.
//   - PPid == 1 rejects a child that zygote64 just forked but hasn't yet
//     renamed (it transiently still shows argv[0]=="zygote64"); only the real
//     zygote is parented to init.
//
// Without exactness the winner was just the first comm∈{main,zygote64,zygote}
// match in /proc order, and os.ReadDir sorts pids lexicographically as strings,
// so which process won depended on the per-boot PID lottery. That is why
// injection worked for a whole uptime, then silently targeted the wrong
// process after a reboot reshuffled the pids. No fork+exec.
func FindProcessPid(processName string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, f := range entries {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		// argv[0] is the first NUL-delimited token; bytes.Cut returns the whole
		// slice when there is no NUL.
		argv0, _, _ := bytes.Cut(cmdline, []byte{0})
		if string(argv0) != processName {
			continue
		}
		ppid, ok := ppidOf(pid)
		if !ok {
			continue
		}
		if ppid != 1 {
			// Right argv[0] but not a child of init: a freshly forked, not-yet-
			// renamed zygote child, not the real zygote. Logging it makes the
			// old failure mode (silently trapping the wrong pid) visible.
			logger.Debug("skip non-init process with matching argv0",
				"name", processName, "pid", pid, "ppid", ppid)
			continue
		}
		return pid, nil
	}
	return 0, fmt.Errorf("process %s not found (no cmdline argv0=%q child of init)", processName, processName)
}

// ChildrenOf returns the live child pids of `parentPid` by scanning /proc
// and parsing each process's stat file for its PPid field. PPid lives right
// after the closing ')' of the (...)-quoted comm. In-process, no fork+exec.
func ChildrenOf(parentPid int) map[int]bool {
	result := make(map[int]bool)
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
		if ppid, ok := ppidOf(pid); ok && ppid == parentPid {
			result[pid] = true
		}
	}
	return result
}

// IsProcessAlive returns true if /proc/<pid> exists.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// ForceStopApp invokes `am force-stop <pkg>` to terminate any running app instance.
func ForceStopApp(pkgName string) error {
	return exec.Command("am", "force-stop", pkgName).Run()
}

// AppProcessAlive returns true iff any process's cmdline starts with `pkgName`
// (followed by NUL for the main process or ':' for app sub-processes like
// `pkg:webview`). This is how Android apps name themselves in /proc/<pid>/cmdline
// after Process.setArgV0.
func AppProcessAlive(pkgName string) bool {
	needle := []byte(pkgName)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", e.Name()))
		if err != nil || !bytes.HasPrefix(cmdline, needle) {
			continue
		}
		if len(cmdline) == len(needle) {
			return true
		}
		switch cmdline[len(needle)] {
		case 0, ':':
			return true
		}
	}
	return false
}

// WaitForAppGone polls until no process for pkgName remains, or `timeout`
// elapses. Returns true if the app exited, false on timeout. Replaces the
// fixed `time.Sleep` after `am force-stop` — SIGKILL is delivered immediately
// so the typical loop iteration count is 0–1.
func WaitForAppGone(pkgName string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	const interval = 10 * time.Millisecond
	for {
		if !AppProcessAlive(pkgName) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// ResolveMainActivity returns the canonical launcher activity for a package
// (component spec `pkg/.Activity`). Tries `cmd package resolve-activity` first,
// falls back to `pm dump` parsing.
func ResolveMainActivity(pkgName string) (string, error) {
	if out, err := exec.Command("cmd", "package", "resolve-activity", "--user", "0", pkgName).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if _, after, ok := strings.Cut(line, "component="); ok {
				if rest := strings.Fields(after); len(rest) > 0 {
					return rest[0], nil
				}
			}
		}
	}

	out, err := exec.Command("pm", "dump", pkgName).CombinedOutput()
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	foundMain := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "android.intent.action.MAIN:") {
			foundMain = true
			continue
		}
		if foundMain && strings.Contains(line, pkgName) {
			for _, f := range strings.Fields(line) {
				if strings.Contains(f, "/") {
					return f, nil
				}
			}
		}
	}
	return "", fmt.Errorf("could not find main activity for %s", pkgName)
}

// GetAppUID returns the uid that owns /data/data/<pkg>. Zero on failure.
func GetAppUID(pkgName string) int {
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/data/data/%s", pkgName), &st); err != nil {
		return 0
	}
	return int(st.Uid)
}

// GetAndroidAPILevel reads ro.build.version.sdk straight from /system/build.prop.
// Cached on first call; falls back to a reasonable default if the prop is
// unreadable or malformed.
var cachedAPILevel int

func GetAndroidAPILevel() int {
	if cachedAPILevel != 0 {
		return cachedAPILevel
	}
	const (
		fallback = 33
		key      = "ro.build.version.sdk="
	)
	data, err := os.ReadFile("/system/build.prop")
	if err != nil {
		cachedAPILevel = fallback
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, key); ok {
			if lvl, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && lvl > 0 {
				cachedAPILevel = lvl
				return lvl
			}
		}
	}
	cachedAPILevel = fallback
	return fallback
}
