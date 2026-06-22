package xfinject

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePayloadByID(t *testing.T) {
	tmp := t.TempDir()
	payload := filepath.Join(tmp, "payload.so")
	data := []byte("fake-so")
	if err := os.WriteFile(payload, data, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	allow := &Allowlist{Payloads: []PayloadDefinition{{ID: "p1", Path: payload, SHA256: hex.EncodeToString(sum[:])}}}
	got, err := ResolvePayloads(Request{PackageName: "com.example.app", PayloadID: "p1"}, allow)
	if err != nil {
		t.Fatalf("ResolvePayloads: %v", err)
	}
	if len(got) != 1 || got[0] != payload {
		t.Fatalf("unexpected payloads: %#v", got)
	}
}

func TestDirectPayloadRequiresAllowlist(t *testing.T) {
	_, err := ResolvePayloads(Request{PackageName: "com.example.app", PayloadPath: "/data/local/tmp/payload.so"}, nil)
	if err == nil {
		t.Fatal("expected direct path rejection without allowlist")
	}
}

func TestDirectPayloadDebugPrefix(t *testing.T) {
	allow := &Allowlist{AllowDirectPaths: true, DebugPathPrefixes: []string{"/data/local/tmp"}}
	got, err := ResolvePayloads(Request{PackageName: "com.example.app", PayloadPath: "/data/local/tmp/payload.so"}, allow)
	if err != nil {
		t.Fatalf("ResolvePayloads: %v", err)
	}
	if len(got) != 1 || got[0] != "/data/local/tmp/payload.so" {
		t.Fatalf("unexpected payloads: %#v", got)
	}
}

func TestValidatePackageName(t *testing.T) {
	for _, pkg := range []string{"com.example.app", "a.b_1.C"} {
		if err := validatePackageName(pkg); err != nil {
			t.Fatalf("valid package rejected %q: %v", pkg, err)
		}
	}
	for _, pkg := range []string{"", ".bad", "bad.", "bad/name", "bad..name"} {
		if err := validatePackageName(pkg); err == nil {
			t.Fatalf("invalid package accepted %q", pkg)
		}
	}
}
