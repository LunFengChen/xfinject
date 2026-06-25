package xfinject

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	BackendZygoteTrap      = "zygote-trap"
	DefaultAllowlistPath   = "/product/etc/xfinject/payloads.json"
	DefaultPayloadRoot     = "/product/lib64/xfinject"
	DefaultDebugPayloadDir = "/data/local/tmp"
)

// Request is the service-facing JSON contract for one injection operation.
// Payloads can be referenced by stable IDs from an allowlist, or by direct paths
// only when the allowlist explicitly permits debug prefixes.
type Request struct {
	PackageName     string      `json:"package"`
	PayloadID       string      `json:"payload_id,omitempty"`
	PayloadIDs      []string    `json:"payload_ids,omitempty"`
	PayloadPath     string      `json:"payload_path,omitempty"`
	PayloadPaths    []string    `json:"payload_paths,omitempty"`
	Backend         string      `json:"backend,omitempty"`
	VmaHide         string      `json:"vma_hide,omitempty"`
	Debug           bool        `json:"debug,omitempty"`
	Logcat          bool        `json:"logcat,omitempty"`
	LogTags         []string    `json:"log_tags,omitempty"`
	ForceStop       *bool       `json:"force_stop,omitempty"`
	WaitForLaunch   bool        `json:"wait_for_launch,omitempty"`
	AutostartSymbol string      `json:"autostart_symbol,omitempty"`
	AutostartArg    string      `json:"autostart_arg,omitempty"`
	Hide            HideRequest `json:"hide,omitempty"`
}

// HideRequest reserves the service contract for kernel-side maps hiding.
// The current backend is xfvmahide KPM, driven through KernelPatch supercall.
type HideRequest struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Mode        string `json:"mode,omitempty"` // "none" | "kpm"
	ProcPath    string `json:"proc_path,omitempty"`
	ClearBefore bool   `json:"clear_before,omitempty"`
}

// Result is returned by request-mode callers and is intentionally JSON-friendly
// for future socket/Binder wrappers.
type Result struct {
	ChildPID int      `json:"child_pid"`
	Payloads []string `json:"payloads"`
	Backend  string   `json:"backend"`
	KPM      string   `json:"kpm,omitempty"`
}

type PayloadDefinition struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256,omitempty"`
	Description string `json:"description,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
}

type Allowlist struct {
	Version           int                 `json:"version"`
	Payloads          []PayloadDefinition `json:"payloads"`
	AllowDirectPaths  bool                `json:"allow_direct_paths,omitempty"`
	DebugPathPrefixes []string            `json:"debug_path_prefixes,omitempty"`
}

func LoadAllowlist(path string) (*Allowlist, error) {
	if path == "" {
		path = DefaultAllowlistPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist %q: %w", path, err)
	}
	var allow Allowlist
	if err := json.Unmarshal(data, &allow); err != nil {
		return nil, fmt.Errorf("parse allowlist %q: %w", path, err)
	}
	return &allow, allow.Validate()
}

func (a *Allowlist) Validate() error {
	if a == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, p := range a.Payloads {
		if p.ID == "" {
			return fmt.Errorf("allowlist payload missing id")
		}
		if seen[p.ID] {
			return fmt.Errorf("duplicate payload id %q", p.ID)
		}
		seen[p.ID] = true
		if err := validatePayloadPath(p.Path); err != nil {
			return fmt.Errorf("payload %q: %w", p.ID, err)
		}
		if p.SHA256 != "" && len(p.SHA256) != 64 {
			return fmt.Errorf("payload %q: invalid sha256 length", p.ID)
		}
	}
	for _, prefix := range a.DebugPathPrefixes {
		if !filepath.IsAbs(prefix) {
			return fmt.Errorf("debug path prefix must be absolute: %q", prefix)
		}
	}
	return nil
}

func RunRequestJSON(data []byte, allow *Allowlist) (*Result, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse request json: %w", err)
	}
	return RunRequest(req, allow)
}

func RunRequest(req Request, allow *Allowlist) (*Result, error) {
	if err := validatePackageName(req.PackageName); err != nil {
		return nil, err
	}
	backend := strings.TrimSpace(req.Backend)
	if backend == "" {
		backend = BackendZygoteTrap
	}
	if backend != BackendZygoteTrap {
		return nil, fmt.Errorf("unsupported backend %q (only %q is implemented)", backend, BackendZygoteTrap)
	}
	payloads, err := ResolvePayloads(req, allow)
	if err != nil {
		return nil, err
	}

	kpmStatus := "disabled"
	if req.Hide.Enabled {
		kpmStatus = "requested"
		if req.Hide.Mode == "" || req.Hide.Mode == "kpm" {
			if req.Hide.ClearBefore {
				client := ProcKPMClient{Path: req.Hide.ProcPath}
				if err := client.ClearUID(GetAppUID(req.PackageName)); err != nil {
					logger.Warn("kpm clear before injection failed", "package", req.PackageName, "error", err)
					kpmStatus = "clear-failed"
				} else {
					kpmStatus = "precleared"
				}
			}
			logger.Warn("kpm hide requested; range registration is reserved for future backend result")
		} else if req.Hide.Mode != "none" {
			return nil, fmt.Errorf("unsupported hide mode %q", req.Hide.Mode)
		}
	}

	forceStop := true
	if req.ForceStop != nil {
		forceStop = *req.ForceStop
	}
	childPid, err := Run(Options{
		PackageName:     req.PackageName,
		LibPaths:        payloads,
		Debug:           req.Debug,
		Logcat:          req.Logcat,
		LogTags:         req.LogTags,
		VmaHide:         req.VmaHide,
		ForceStop:       forceStop,
		WaitForLaunch:   req.WaitForLaunch,
		AutostartSymbol: req.AutostartSymbol,
		AutostartArg:    req.AutostartArg,
	})
	if err != nil {
		return nil, err
	}
	return &Result{ChildPID: childPid, Payloads: payloads, Backend: backend, KPM: kpmStatus}, nil
}

func ResolvePayloads(req Request, allow *Allowlist) ([]string, error) {
	ids := append([]string{}, req.PayloadIDs...)
	if req.PayloadID != "" {
		ids = append(ids, req.PayloadID)
	}
	paths := append([]string{}, req.PayloadPaths...)
	if req.PayloadPath != "" {
		paths = append(paths, req.PayloadPath)
	}

	resolved := make([]string, 0, len(ids)+len(paths))
	for _, id := range ids {
		path, err := allow.ResolveID(id)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, path)
	}
	for _, path := range paths {
		if allow == nil || !allow.AllowDirectPaths {
			return nil, fmt.Errorf("direct payload path %q rejected: allowlist does not enable allow_direct_paths", path)
		}
		if err := validatePayloadPath(path); err != nil {
			return nil, err
		}
		if !allow.pathAllowed(path) {
			return nil, fmt.Errorf("direct payload path %q is outside debug prefixes", path)
		}
		resolved = append(resolved, filepath.Clean(path))
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("request contains no payloads")
	}
	return resolved, nil
}

func (a *Allowlist) ResolveID(id string) (string, error) {
	if a == nil {
		return "", fmt.Errorf("payload id %q requires an allowlist", id)
	}
	for _, p := range a.Payloads {
		if p.ID != id {
			continue
		}
		if p.Disabled {
			return "", fmt.Errorf("payload %q is disabled", id)
		}
		if p.SHA256 != "" {
			if err := verifySHA256(p.Path, p.SHA256); err != nil {
				return "", fmt.Errorf("payload %q integrity check failed: %w", id, err)
			}
		}
		return filepath.Clean(p.Path), nil
	}
	return "", fmt.Errorf("payload id %q not found in allowlist", id)
}

func (a *Allowlist) pathAllowed(path string) bool {
	clean := filepath.Clean(path)
	prefixes := a.DebugPathPrefixes
	if len(prefixes) == 0 {
		prefixes = []string{DefaultDebugPayloadDir}
	}
	for _, prefix := range prefixes {
		prefix = filepath.Clean(prefix)
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func validatePackageName(pkg string) error {
	if pkg == "" {
		return fmt.Errorf("package name is required")
	}
	if strings.Contains(pkg, "..") || strings.HasPrefix(pkg, ".") || strings.HasSuffix(pkg, ".") {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	for _, r := range pkg {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid package name %q", pkg)
	}
	return nil
}

func validatePayloadPath(path string) error {
	if path == "" {
		return fmt.Errorf("payload path is empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("payload path must be absolute: %q", path)
	}
	clean := filepath.Clean(path)
	if !strings.HasSuffix(clean, ".so") {
		return fmt.Errorf("payload path must end with .so: %q", path)
	}
	return nil
}

func verifySHA256(path, wantHex string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, wantHex) {
		return fmt.Errorf("sha256 mismatch got=%s want=%s", got, wantHex)
	}
	return nil
}

// ProcKPMClient is a tiny placeholder for the future kernel/KPM hide ABI.
type ProcKPMClient struct {
	Path string
}

func (c ProcKPMClient) path() string {
	if c.Path == "" {
		return "xfvmahide:kpm"
	}
	return c.Path
}

func (c ProcKPMClient) ClearUID(uid int) error {
	if uid <= 0 {
		return fmt.Errorf("invalid uid %d", uid)
	}
	return os.WriteFile(c.path(), []byte(fmt.Sprintf("clear %d\n", uid)), 0600)
}

func (c ProcKPMClient) Add(uid int, start, end uint64, tag string) error {
	if uid <= 0 || start == 0 || end <= start {
		return fmt.Errorf("invalid hide range uid=%d start=0x%x end=0x%x", uid, start, end)
	}
	if tag == "" {
		tag = "payload"
	}
	line := fmt.Sprintf("add %d 0x%x 0x%x %s\n", uid, start, end, tag)
	return os.WriteFile(c.path(), []byte(line), 0600)
}
