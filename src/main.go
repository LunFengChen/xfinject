package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// stringSlice collects a repeatable string flag into an ordered slice, so
// `-lib a.so -lib b.so` yields ["a.so", "b.so"] in command-line order.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	pkgName := flag.String("pkg", "", "target package name (e.g. com.example.app)")
	var libPaths stringSlice
	flag.Var(&libPaths, "lib", "path to native library to inject (repeatable; injected in order)")
	debug := flag.Bool("debug", false, "enable debug logging")
	logcat := flag.Bool("logcat", false, "stream logcat for the injected child after dlopen")
	var logTags stringSlice
	flag.Var(&logTags, "logtag", "stream logcat filtered to this tag (raw format; repeatable); implies -logcat")
	vmaHide := flag.String("vma-hide", "auto", "/proc/vma_hide use: auto (on iff the module is present) | always | never")

	flag.Parse()

	if *pkgName == "" || len(libPaths) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if *debug {
		if err := SetLogLevel("debug"); err != nil {
			logger.Error("set log level", "error", err)
		}
	}
	SetVmaHideMode(*vmaHide)

	logger.Info("injector start", "package", *pkgName, "payloads", len(libPaths))
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

	// Stage one sandbox copy per payload, preserving command-line order so the
	// stage dlopens them in the same sequence.
	stagedPaths := make([]string, 0, len(libPaths))
	// Remove every staged sandbox copy made so far. Used on the failure paths
	// below — os.Exit does not run defers, so cleanup is explicit. The success
	// path removes the copies inside RunInjector once every dlopen has completed.
	cleanupStaged := func() {
		for _, p := range stagedPaths {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				logger.Debug("staged payload cleanup failed", "path", p, "error", err)
			}
		}
	}
	for i, libPath := range libPaths {
		stagedPath, err := stagePayloadCopy(*pkgName, libPath)
		if err != nil {
			logger.Error("stage payload failed", "index", i, "payload", libPath, "error", err)
			cleanupStaged()
			os.Exit(1)
		}
		logger.Debug("payload staged", "index", i, "path", stagedPath)
		stagedPaths = append(stagedPaths, stagedPath)
	}

	childPid, err := RunInjector(*pkgName, stagedPaths, zygotePid, mainActivity, apiLevel)
	if err != nil {
		logger.Error("injection failed", "error", err)
		cleanupStaged()
		os.Exit(1)
	}

	// -logtag implies -logcat: a tag filter still wants the same streaming flow,
	// so the operator never has to pass both.
	if (*logcat || len(logTags) > 0) && childPid > 0 {
		streamLogcat(*pkgName, childPid, logTags)
	}
}

// streamLogcat tails logcat for the freshly injected child and blocks until one
// of three things ends it: the child process exits, the operator interrupts
// (Ctrl-C / SIGTERM), or logcat itself dies. `logcat --pid` does NOT stop when
// the pid dies, so a /proc liveness poll cancels the stream when the child is
// gone — otherwise the tool would hang on a dead app. On return — for any reason
// — it stops the target (if still alive), binding the app's lifetime to the
// tool's. When tags is non-empty the stream is raw-format output filtered to
// those log tags (logcat's `-s tag...` filterspec — exact-tag, not regex);
// either way it is scoped to childPid.
func streamLogcat(pkgName string, childPid int, tags []string) {
	args := []string{"-v", "brief", fmt.Sprintf("--pid=%d", childPid)}
	if len(tags) > 0 {
		// `-s` silences the default filter, then each tag is whitelisted as its
		// own filterspec argument, so `-s A B` prints only tags A and B.
		args[1] = "raw"
		args = append(args, "-s")
		args = append(args, tags...)
		logger.Info("streaming logcat", "tags", strings.Join(tags, ","), "child_pid", childPid)
	} else {
		logger.Info("streaming logcat", "child_pid", childPid)
	}

	// Cancelling ctx kills the logcat process; both the child-death watcher and
	// the signal handler use it to stop the stream.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, "logcat", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Own process group so a terminal Ctrl-C is delivered to us, not straight to
	// logcat — we catch it, stop the stream, and tear the target down ourselves.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// However we leave, stop the injected target if it is still alive.
	defer stopChild(pkgName, childPid)

	if err := cmd.Start(); err != nil {
		logger.Warn("logcat start failed", "error", err)
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	// Watch the child and the operator. Pairing the pid with its start time
	// avoids a pid-reuse false "alive" if the kernel recycles the pid mid-poll.
	startTime, haveStartTime := procStartTime(childPid)
	reason := make(chan string, 1)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigs:
				reason <- "interrupted"
				cancel()
				return
			case <-ticker.C:
				var gone bool
				if haveStartTime {
					cur, ok := procStartTime(childPid)
					gone = !ok || cur != startTime
				} else {
					gone = !IsProcessAlive(childPid)
				}
				if gone {
					reason <- "child-exited"
					cancel()
					return
				}
			}
		}
	}()

	_ = cmd.Wait()
	select {
	case r := <-reason:
		if r == "interrupted" {
			logger.Info("interrupted, stopping logcat", "child_pid", childPid)
		} else {
			logger.Info("child exited, stopping logcat", "child_pid", childPid)
		}
	default:
		logger.Info("logcat exited", "child_pid", childPid)
	}
}

// stopChild binds the injected target's lifetime to the tool's: on exit in
// -logcat / -logtag mode it kills the spawned pid and force-stops the package so
// no sibling processes linger. It no-ops quietly when the app has already exited
// on its own (the common case when the stream ended because the child died).
func stopChild(pkgName string, childPid int) {
	if childPid > 0 && IsProcessAlive(childPid) {
		if err := syscall.Kill(childPid, syscall.SIGKILL); err != nil {
			logger.Debug("kill child failed", "child_pid", childPid, "error", err)
		}
	}
	if AppProcessAlive(pkgName) {
		if err := ForceStopApp(pkgName); err != nil {
			logger.Warn("force-stop on exit failed", "package", pkgName, "error", err)
		}
		logger.Info("stopped target on exit", "package", pkgName)
	}
}

// writeIntoAppSandbox writes data as <name> under the target app's data dir
// when accessible, falling back to /data/local/tmp. The file is chowned to uid
// so an open() inside the child's untrusted_app SELinux context succeeds
// without an audit-visible 'granted' line on app_data_file from a foreign path.
func writeIntoAppSandbox(pkgName, name string, data []byte, perm os.FileMode, uid int) (string, error) {
	for _, dir := range []string{fmt.Sprintf("/data/data/%s", pkgName), "/data/local/tmp"} {
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			logger.Debug("mkdir failed", "path", dir, "error", err)
			continue
		}
		if err := os.WriteFile(dst, data, perm); err != nil {
			logger.Debug("write failed", "path", dst, "error", err)
			continue
		}
		if uid > 0 {
			if err := syscall.Chown(dst, uid, -1); err != nil {
				logger.Debug("chown failed", "path", dst, "uid", uid, "error", err)
			}
		}
		return dst, nil
	}
	return "", fmt.Errorf("all staging directories failed for %s", name)
}

// randomChromiumName returns an innocuous chromium-cache-style file name with
// a fresh 64-bit random suffix.  Used for both the persistent payload copy and
// the transient stage file so they blend with normal webview artifacts.
func randomChromiumName() (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("random name: %w", err)
	}
	return fmt.Sprintf(".org.chromium.%s.tmp", hex.EncodeToString(rnd[:])), nil
}

// stagePayloadCopy copies the user-supplied payload into the app sandbox so
// the stage's dlopen() inside the child can open it cleanly.  Only the COPY is
// ever referenced; the user's source file is never touched.
func stagePayloadCopy(pkgName string, srcPath string) (string, error) {
	payload, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("read source payload %q: %w", srcPath, err)
	}
	name, err := randomChromiumName()
	if err != nil {
		return "", err
	}
	return writeIntoAppSandbox(pkgName, name, payload, 0644, GetAppUID(pkgName))
}
