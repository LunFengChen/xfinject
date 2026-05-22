package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	pkgName := flag.String("pkg", "", "target package name (e.g. com.example.app)")
	libPath := flag.String("lib", "", "path to native library to inject")
	debug := flag.Bool("debug", false, "enable debug logging")
	logcat := flag.Bool("logcat", false, "stream logcat for the injected child after dlopen")

	flag.Parse()

	if *pkgName == "" || *libPath == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *debug {
		if err := SetLogLevel("debug"); err != nil {
			logger.Error("set log level", "error", err)
		}
	}

	logger.Info("injector start", "package", *pkgName, "payload", *libPath)
	apiLevel := GetAndroidAPILevel()
	logger.Debug("detected android api", "api", apiLevel)

	if AppProcessAlive(*pkgName) {
		logger.Debug("force-stop", "package", *pkgName)
		if err := ForceStopApp(*pkgName); err != nil {
			logger.Warn("force-stop failed", "package", *pkgName, "error", err)
		}
		if !WaitForAppGone(*pkgName, 2*time.Second) {
			logger.Warn("app still alive after force-stop", "package", *pkgName)
		}
	}

	zygotePid, err := FindProcessPid("zygote64")
	if err != nil {
		logger.Error("zygote64 not found", "error", err)
		os.Exit(1)
	}
	logger.Info("zygote located", "zygote_pid", zygotePid)

	mainActivity, err := ResolveMainActivity(*pkgName)
	if err != nil {
		logger.Warn("resolve activity failed", "package", *pkgName, "error", err)
		mainActivity = fmt.Sprintf("%s/.MainActivity", *pkgName)
	} else {
		logger.Info("resolved activity", "package", *pkgName, "activity", mainActivity)
	}

	stagedPath, err := stagePayloadCopy(*pkgName, *libPath)
	if err != nil {
		logger.Error("stage payload failed", "error", err)
		os.Exit(1)
	}
	logger.Debug("payload staged", "path", stagedPath)

	childPid, err := RunInjector(*pkgName, stagedPath, zygotePid, mainActivity, apiLevel)
	if err != nil {
		logger.Error("injection failed", "error", err)
		os.Exit(1)
	}

	if *logcat && childPid > 0 {
		logger.Info("streaming logcat", "child_pid", childPid)
		cmd := exec.Command("logcat", "-v", "brief", fmt.Sprintf("--pid=%d", childPid))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
}

// stagePayloadCopy copies the user-supplied payload into a location the target
// app process can dlopen. Prefers /data/data/<pkg> (DAC-protected, app-owned)
// and falls back to /data/local/tmp. The copy is chowned to the app uid so
// the stage's open() inside the child succeeds without selinux contortions.
// Only the COPY is ever referenced by the stage — the user's source file is
// never touched.
func stagePayloadCopy(pkgName string, srcPath string) (string, error) {
	payload, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("read source payload %q: %w", srcPath, err)
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("random name: %w", err)
	}
	name := fmt.Sprintf(".org.chromium.%s.tmp", hex.EncodeToString(rnd[:]))

	uid := GetAppUID(pkgName)
	dirs := []string{fmt.Sprintf("/data/data/%s", pkgName), "/data/local/tmp"}

	for _, dir := range dirs {
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			logger.Debug("mkdir failed", "path", dir, "error", err)
			continue
		}
		if err := os.WriteFile(dst, payload, 0644); err != nil {
			logger.Debug("write payload failed", "path", dst, "error", err)
			continue
		}
		if uid > 0 {
			if err := syscall.Chown(dst, uid, -1); err != nil {
				logger.Debug("chown failed", "path", dst, "uid", uid, "error", err)
			}
		}
		return dst, nil
	}
	return "", fmt.Errorf("all staging directories failed")
}
