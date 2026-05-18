package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// validZygoteComm returns true if the comm of the process indicates it's
// the actual zygote, not a forked app that inherited the zygote cmdline.
// Zygote64's name is "main" (set by prctl PR_SET_NAME). Forked apps show
// their package name, shells show "sh", etc.
func validZygoteComm(comm string) bool {
	switch strings.TrimSpace(comm) {
	case "main", "zygote64", "zygote":
		return true
	}
	return false
}

func FindProcessPid(processName string) (int, error) {
	// Use pgrep -f to find candidates, then verify comm to exclude
	// shell processes running the pgrep command itself, forked apps that
	// still show the zygote cmdline, etc.
	out, err := exec.Command("pgrep", "-f", processName).Output()
	if err == nil {
		pids := strings.Fields(string(out))
		for _, pidStr := range pids {
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}
			commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err != nil {
				continue
			}
			if validZygoteComm(string(commData)) {
				return pid, nil
			}
		}
	}

	// Fallback: scan /proc manually matching both cmdline and comm
	files, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err == nil && validZygoteComm(string(commData)) {
			return pid, nil
		}

		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		s := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte(" ")))
		if strings.Contains(s, processName) {
			// Found by cmdline — verify comm isn't a package name
			commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err == nil && !validZygoteComm(string(commData)) {
				continue // skip forked apps that inherited the cmdline
			}
			return pid, nil
		}
	}

	return 0, fmt.Errorf("process %s not found", processName)
}

func ForceStopApp(pkgName string) error {
	cmd := exec.Command("am", "force-stop", pkgName)
	return cmd.Run()
}

func FindNewestChildPid(parentPid int, match string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("pgrep", "-P", strconv.Itoa(parentPid)).Output()
		pids := strings.Fields(string(out))

		for i := len(pids) - 1; i >= 0; i-- {
			pid, err := strconv.Atoi(pids[i])
			if err != nil {
				continue
			}
			if match == "" {
				return pid, nil
			}
			cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if err != nil {
				continue
			}
			s := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte(" ")))
			if strings.Contains(s, match) {
				return pid, nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	return 0, fmt.Errorf("no child of %d matched %q", parentPid, match)
}

func WaitForProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func ResolveMainActivity(pkgName string) (string, error) {
	output, err := exec.Command("cmd", "package", "resolve-activity", "--user", "0", pkgName).Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "component=") {
				parts := strings.Split(line, "component=")
				if len(parts) > 1 {
					return strings.Fields(parts[1])[0], nil
				}
			}
		}
	}

	output, err = exec.Command("pm", "dump", pkgName).CombinedOutput()
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	foundMain := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "android.intent.action.MAIN:") {
			foundMain = true
			continue
		}
		if foundMain && strings.Contains(line, pkgName) {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.Contains(f, "/") {
					return f, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find main activity for %s", pkgName)
}
