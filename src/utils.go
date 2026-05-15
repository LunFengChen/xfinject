package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func FindProcessPid(processName string) (int, error) {
	// Try pgrep first as it is more robust
	out, err := exec.Command("pgrep", "-f", processName).Output()
	if err == nil {
		pids := strings.Fields(string(out))
		if len(pids) > 0 {
			return strconv.Atoi(pids[0])
		}
	}

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

		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err == nil {
			// cmdline contains null-terminated strings
			s := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte(" ")))
			if strings.Contains(s, processName) {
				return pid, nil
			}
		}

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err == nil && strings.TrimSpace(string(comm)) == processName {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("process %s not found", processName)
}

func ForceStopApp(pkgName string) error {
	cmd := exec.Command("am", "force-stop", pkgName)
	return cmd.Run()
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
