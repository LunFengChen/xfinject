package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	pkgName := flag.String("pkg", "pkg", "target package name (e.g. com.termux)")
	libPath := flag.String("lib", "lib", "path to native library to inject")
	debug := flag.Bool("debug", false, "enable debug logging")
	memfd := flag.Bool("memfd", false, "use memfd_create for fileless injection (requires kernel support)")
	logcat := flag.Bool("logcat", false, "start logcat for child pid after inject")

	flag.Parse()

	if *debug {
		SetLogLevel("debug")
	}

	if *pkgName == "" || *libPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	LogInfo("starting spawn injector", "package", *pkgName, "payload", *libPath)

	// Step 1: Kill existing app instance
	LogDebug("killing existing app instance", "package", *pkgName)
	err := ForceStopApp(*pkgName)
	if err != nil {
		LogWarn("failed to force-stop app", "error", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Step 2: Locate zygote64
	LogDebug("locating zygote64")
	zygotePid, err := FindProcessPid("zygote64")
	if err != nil {
		LogError("could not find zygote64 pid", "error", err)
		os.Exit(1)
	}
	LogInfo("found zygote64", "pid", zygotePid)

	// Step 3: Resolve main activity
	LogDebug("resolving main activity", "package", *pkgName)
	mainActivity, err := ResolveMainActivity(*pkgName)
	if err != nil {
		LogWarn("could not resolve main activity", "error", err)
		mainActivity = fmt.Sprintf("%s/.MainActivity", *pkgName)
	} else {
		LogInfo("resolved main activity", "package", *pkgName, "activity", mainActivity)
	}

	// Step 4: Inject via selected path
	var childPid int

	if *memfd {
		childPid, err = RunMemfdInjector(*pkgName, *libPath, zygotePid, mainActivity)
	} else {
		// Default: staged file injection.  Copy payload to /data/data/<pkgname>/,
		// chown to app UID, dlopen from there.  The file persists on disk.
		stagedPath, err := stageEphemeralPayload(*pkgName, *libPath)
		if err != nil {
			LogError("failed to stage ephemeral payload", "error", err)
			os.Exit(1)
		}
		LogDebug("staged ephemeral payload", "path", stagedPath)

		childPid, err = RunInjector(*pkgName, stagedPath, zygotePid, mainActivity)
	}

	if err != nil {
		LogError("injection failed", "error", err)
		os.Exit(1)
	}

	LogInfo("injection sequence complete", "pid", childPid)

	if *logcat && childPid > 0 {
		LogInfo("starting logcat", "pid", childPid)
		cmd := exec.Command("logcat", "-v", "brief", fmt.Sprintf("--pid=%d", childPid))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
}

// stageEphemeralPayload copies the user-supplied payload to /data/data/<pkgname>/
// with the app's UID so the child process can dlopen it.  The original srcPath is
// never modified or deleted.
func stageEphemeralPayload(pkgName string, srcPath string) (string, error) {
	stagingDir := fmt.Sprintf("/data/data/%s", pkgName)

	payloadData, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to read original payload %q: %w", srcPath, err)
	}

	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random name: %w", err)
	}

	stagedName := fmt.Sprintf(".org.chromium.%s.tmp", hex.EncodeToString(randomBytes))
	stagedPath := filepath.Join(stagingDir, stagedName)

	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create staging dir %q: %w", stagingDir, err)
	}

	if err := os.WriteFile(stagedPath, payloadData, 0755); err != nil {
		return "", fmt.Errorf("failed to write staged payload to %q: %w", stagedPath, err)
	}

	uid := getAppUid(pkgName)
	if uid > 0 {
		if err := os.Chown(stagedPath, uid, -1); err != nil {
			LogWarn("failed to chown staged payload to app uid", "uid", uid, "error", err)
		} else {
			LogDebug("chowned staged payload to app uid", "uid", uid)
		}
	}

	return stagedPath, nil
}

func getAppUid(pkgName string) int {
	out, err := exec.Command("stat", "-c", "%u", fmt.Sprintf("/data/data/%s", pkgName)).Output()
	if err != nil {
		return 0
	}
	var uid int
	fmt.Sscanf(string(out), "%d", &uid)
	return uid
}
