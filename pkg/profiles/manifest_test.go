package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveArtifactsServePath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "installer"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	filePath := filepath.Join(root, "installer", "vmlinuz")
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	profile := &Profile{
		ID:   "deviceA",
		Name: "Device A",
		Network: NetworkConfig{
			ServerIP: "192.168.77.1",
			CIDR:     "192.168.77.1/24",
		},
		Boot: BootConfig{
			HTTPRoot: "http",
		},
		Artifacts: Artifacts{
			HTTPFiles: []string{"installer/vmlinuz"},
		},
	}

	manifest, err := ResolveArtifacts(profile, []string{root})
	if err != nil {
		t.Fatalf("ResolveArtifacts: %v", err)
	}
	if len(manifest.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(manifest.Files))
	}
	if got := manifest.Files[0].ServePath; got != "/http/installer/vmlinuz" {
		t.Fatalf("serve path mismatch: %s", got)
	}
}

func TestResolveArtifactsRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	profile := &Profile{
		ID:   "deviceA",
		Name: "Device A",
		Network: NetworkConfig{
			ServerIP: "192.168.77.1",
			CIDR:     "192.168.77.1/24",
		},
		Boot: BootConfig{},
		Artifacts: Artifacts{
			HTTPFiles: []string{"../secrets.txt"},
		},
	}
	if _, err := ResolveArtifacts(profile, []string{root}); err == nil {
		t.Fatal("expected error for path traversal")
	}
}
