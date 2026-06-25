package xfinject

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

// Options describes one xfinject run.
type Options struct {
	PackageName     string
	LibPaths        []string
	Debug           bool
	Logcat          bool
	LogTags         []string
	VmaHide         string
	ForceStop       bool
	WaitForLaunch   bool
	WaitTimeout     time.Duration
	AutostartSymbol string
	AutostartArg    string
}

// stringSlice collects a repeatable string flag into an ordered slice, so
// `-lib a.so -lib b.so` yields ["a.so", "b.so"] in command-line order.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// InjectByPackage is the small library entry point used by wrappers/daemons.
// It injects libPaths into a freshly-started target package and returns the
// child pid that loaded the payloads.
func InjectByPackage(pkgName string, libPaths []string) (int, error) {
	return Run(Options{
		PackageName: pkgName,
		LibPaths:    libPaths,
		VmaHide:     "auto",
		ForceStop:   true,
	})
}

// Run executes one injection request. It is intentionally close to the original
// xfinject CLI flow, but reusable from xfinjectd or c-shared wrappers.
func Run(opts Options) (int, error) {
	if opts.PackageName == "" {
		return 0, fmt.Errorf("package name is required")
	}
	if len(opts.LibPaths) == 0 {
		return 0, fmt.Errorf("at least one payload library is required")
	}
	if opts.VmaHide == "" {
		opts.VmaHide = "auto"
	}
	if opts.Debug {
		if err := SetLogLevel("debug"); err != nil {
			logger.Error("set log level", "error", err)
		}
	}
	SetVmaHideMode(opts.VmaHide)

	logger.Info("xfinject start", "package", opts.PackageName, "payloads", len(opts.LibPaths))
	apiLevel := GetAndroidAPILevel()
	logger.Debug("detected android api", "api", apiLevel)

	if opts.ForceStop && !opts.WaitForLaunch && AppProcessAlive(opts.PackageName) {
		logger.Debug("force-stop", "package", opts.PackageName)
		if err := ForceStopApp(opts.PackageName); err != nil {
			logger.Warn("force-stop failed", "package", opts.PackageName, "error", err)
		}
		if !WaitForAppGone(opts.PackageName, 2*time.Second) {
			logger.Warn("app still alive after force-stop", "package", opts.PackageName)
		}
	}

	zygotePid, err := FindProcessPid("zygote64")
	if err != nil {
		return 0, fmt.Errorf("zygote64 not found: %w", err)
	}
	logger.Info("zygote located", "zygote_pid", zygotePid)

	mainActivity := ""
	if !opts.WaitForLaunch {
		var err error
		mainActivity, err = ResolveMainActivity(opts.PackageName)
		if err != nil {
			logger.Warn("resolve activity failed", "package", opts.PackageName, "error", err)
			mainActivity = fmt.Sprintf("%s/.MainActivity", opts.PackageName)
		} else {
			logger.Info("resolved activity", "package", opts.PackageName, "activity", mainActivity)
		}
	}

	stagedPaths := make([]string, 0, len(opts.LibPaths))
	cleanupStaged := func() {
		for _, p := range stagedPaths {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				logger.Debug("staged payload cleanup failed", "path", p, "error", err)
			}
		}
	}
	for i, libPath := range opts.LibPaths {
		stagedPath, err := stagePayloadCopy(opts.PackageName, libPath)
		if err != nil {
			cleanupStaged()
			return 0, fmt.Errorf("stage payload %d %q: %w", i, libPath, err)
		}
		logger.Debug("payload staged", "index", i, "path", stagedPath)
		stagedPaths = append(stagedPaths, stagedPath)
	}

	childPid, err := RunInjector(opts.PackageName, stagedPaths, zygotePid, mainActivity, apiLevel, !opts.WaitForLaunch, opts.WaitTimeout, opts.AutostartSymbol, opts.AutostartArg)
	if err != nil {
		cleanupStaged()
		return childPid, err
	}

	if (opts.Logcat || len(opts.LogTags) > 0) && childPid > 0 {
		streamLogcat(opts.PackageName, childPid, opts.LogTags)
	}
	return childPid, nil
}

// RunCLI keeps the original command-line UX while allowing the implementation
// to live in package xfinject.
func RunCLI(args []string) int {
	fs := flag.NewFlagSet("xfinjectd", flag.ContinueOnError)
	pkgName := fs.String("pkg", "", "target package name (e.g. com.example.app)")
	var libPaths stringSlice
	fs.Var(&libPaths, "lib", "path to native library to inject (repeatable; injected in order)")
	debug := fs.Bool("debug", false, "enable debug logging")
	logcat := fs.Bool("logcat", false, "stream logcat for the injected child after dlopen")
	var logTags stringSlice
	fs.Var(&logTags, "logtag", "stream logcat filtered to this tag (raw format; repeatable); implies -logcat")
	vmaHide := fs.String("vma-hide", "auto", "xfvmahide use: auto (on iff xfvmahide KPM is loaded) | always | never")
	autostartSymbol := fs.String("autostart-symbol", "", "optional payload symbol to call after dlopen(handle), before unlink")
	autostartArg := fs.String("autostart-arg", "", "optional string argument passed to -autostart-symbol")
	requestPath := fs.String("request", "", "JSON injection request file (service-mode skeleton)")
	allowlistPath := fs.String("allowlist", DefaultAllowlistPath, "payload allowlist JSON path used with -request")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *requestPath != "" {
		data, err := os.ReadFile(*requestPath)
		if err != nil {
			logger.Error("read request failed", "path", *requestPath, "error", err)
			return 1
		}
		allow, err := LoadAllowlist(*allowlistPath)
		if err != nil {
			logger.Error("load allowlist failed", "path", *allowlistPath, "error", err)
			return 1
		}
		result, err := RunRequestJSON(data, allow)
		if err != nil {
			logger.Error("request injection failed", "path", *requestPath, "error", err)
			return 1
		}
		logger.Info("request injection complete", "child_pid", result.ChildPID, "backend", result.Backend, "payloads", len(result.Payloads), "kpm", result.KPM)
		return 0
	}
	if *pkgName == "" || len(libPaths) == 0 {
		fs.Usage()
		return 2
	}
	_, err := Run(Options{
		PackageName:     *pkgName,
		LibPaths:        []string(libPaths),
		Debug:           *debug,
		Logcat:          *logcat,
		LogTags:         []string(logTags),
		VmaHide:         *vmaHide,
		ForceStop:       true,
		AutostartSymbol: *autostartSymbol,
		AutostartArg:    *autostartArg,
	})
	if err != nil {
		logger.Error("injection failed", "error", err)
		return 1
	}
	return 0
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
