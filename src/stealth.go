package main

// Stealth utilities for reducing detection surface.
//
// This file contains helpers used by the injector to minimize forensic
// artifacts that anti-tamper SDKs look for.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScrubProcessArtifacts removes traces of the injector process from the device.
// Called after injection is complete.
func ScrubProcessArtifacts(injectorPath string) {
	// Overwrite the binary with zeros before unlinking to prevent forensic recovery
	if info, err := os.Stat(injectorPath); err == nil {
		zeros := make([]byte, info.Size())
		_ = os.WriteFile(injectorPath, zeros, 0)
	}
	_ = os.Remove(injectorPath)
}

// GenerateStealthName creates a process name that blends with normal Android system processes.
// Anti-tamper tools often scan /proc for suspicious process names.
func GenerateStealthName() string {
	candidates := []string{
		"app_process64",
		"surfaceflinger",
		"servicemanager",
		"hwservicemanager",
		"vold",
		"installd",
		"lmkd",
	}
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return candidates[int(b[0])%len(candidates)]
}

// StagePayloadStealthy stages the payload in a location and with a name that
// won't trigger heuristic file scanners. Returns the staged path.
func StagePayloadStealthy(pkgName string, srcPath string) (string, error) {
	payloadData, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}

	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// Try app-private directories in order of preference
	candidates := []string{
		filepath.Join("/data/data", pkgName, "code_cache"),
		filepath.Join("/data/data", pkgName, "cache"),
		filepath.Join("/data/data", pkgName),
		filepath.Join("/data/user/0", pkgName, "code_cache"),
		filepath.Join("/data/user/0", pkgName),
	}

	var targetDir string
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			targetDir = dir
			break
		}
	}
	if targetDir == "" {
		return "", fmt.Errorf("no suitable staging directory for %s", pkgName)
	}

	// Use a name that looks like a legitimate Android runtime artifact
	// These patterns are common in code_cache and won't trigger scanners:
	//   .overlay_<hex>  (looks like resource overlay cache)
	//   .dex_<hex>      (looks like dex optimization artifact)
	stagedName := fmt.Sprintf(".overlay_%s.odex", hex.EncodeToString(randomBytes))
	stagedPath := filepath.Join(targetDir, stagedName)

	if err := os.WriteFile(stagedPath, payloadData, 0755); err != nil {
		return "", fmt.Errorf("write staged payload: %w", err)
	}

	return stagedPath, nil
}

// ValidateStealthEnvironment checks if the environment is suitable for stealth injection.
// Returns warnings about conditions that might compromise stealth.
func ValidateStealthEnvironment(pid int) []string {
	var warnings []string

	// Check if SELinux is enforcing (payload might get blocked)
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			warnings = append(warnings, "SELinux is enforcing — payload may be blocked by MAC policy")
		}
	}

	// Check if the target has TracerPid set (another debugger attached)
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if data, err := os.ReadFile(statusPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] != "0" {
					warnings = append(warnings, fmt.Sprintf("target pid %d already has a tracer (pid %s)", pid, fields[1]))
				}
			}
		}
	}

	return warnings
}
