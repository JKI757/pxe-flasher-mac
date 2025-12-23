package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type Manifest struct {
	GeneratedAt time.Time      `json:"generated_at"`
	ProfileID   string         `json:"profile_id"`
	ProfileName string         `json:"profile_name"`
	HTTPPrefix  string         `json:"http_prefix"`
	Files       []ManifestFile `json:"files"`
}

type ManifestFile struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	RelPath   string `json:"rel_path"`
	AbsPath   string `json:"abs_path"`
	ServePath string `json:"serve_path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Root      string `json:"root"`
}

func ResolveArtifacts(p *Profile, roots []string) (*Manifest, error) {
	if err := Validate(p); err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("at least one artifact root is required")
	}
	prefix, err := cleanURLPrefix(p.Boot.HTTPRoot)
	if err != nil {
		return nil, err
	}
	tftpPrefix, err := cleanURLPrefix(p.Boot.TFTPRoot)
	if err != nil {
		return nil, err
	}

	manifest := &Manifest{
		GeneratedAt: time.Now().UTC(),
		ProfileID:   p.ID,
		ProfileName: p.Name,
		HTTPPrefix:  prefix,
	}

	servePaths := make(map[string]struct{})
	appendFile := func(kind, relPath string, servePrefix string) error {
		absPath, root, err := resolveArtifactPath(relPath, roots)
		if err != nil {
			return err
		}
		hash, size, err := hashFile(absPath)
		if err != nil {
			return err
		}
		servePath := buildServePath(servePrefix, relPath)
		if _, exists := servePaths[servePath]; exists {
			return fmt.Errorf("duplicate serve path: %s", servePath)
		}
		servePaths[servePath] = struct{}{}
		manifest.Files = append(manifest.Files, ManifestFile{
			ID:        stableID(kind, relPath),
			Kind:      kind,
			RelPath:   relPath,
			AbsPath:   absPath,
			ServePath: servePath,
			Size:      size,
			SHA256:    hash,
			Root:      root,
		})
		return nil
	}

	for _, relPath := range p.Artifacts.TFTPFiles {
		if err := appendFile("tftp", relPath, tftpPrefix); err != nil {
			return nil, fmt.Errorf("tftp file %q: %w", relPath, err)
		}
	}
	for _, relPath := range p.Artifacts.HTTPFiles {
		if err := appendFile("http", relPath, prefix); err != nil {
			return nil, fmt.Errorf("http file %q: %w", relPath, err)
		}
	}

	return manifest, nil
}

func WriteManifest(path string, manifest *Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func resolveArtifactPath(relPath string, roots []string) (string, string, error) {
	if !isSafeRelPath(relPath) {
		return "", "", fmt.Errorf("invalid path")
	}
	cleanRel := filepath.Clean(relPath)
	for _, root := range roots {
		candidate := filepath.Join(root, cleanRel)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("not a regular file")
		}
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			return "", "", err
		}
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return "", "", err
		}
		fileEval, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			return "", "", err
		}
		rootEval, err := filepath.EvalSymlinks(rootAbs)
		if err != nil {
			return "", "", err
		}
		if !isWithinRoot(fileEval, rootEval) {
			return "", "", fmt.Errorf("path escapes root")
		}
		return fileEval, rootEval, nil
	}
	return "", "", fmt.Errorf("not found in artifact roots")
}

func isWithinRoot(pathValue, root string) bool {
	root = strings.TrimSuffix(root, string(filepath.Separator))
	pathValue = strings.TrimSuffix(pathValue, string(filepath.Separator))
	if pathValue == root {
		return true
	}
	if !strings.HasPrefix(pathValue, root+string(filepath.Separator)) {
		return false
	}
	return true
}

func buildServePath(prefix, relPath string) string {
	cleanRel := path.Clean("/" + filepath.ToSlash(relPath))
	cleanRel = strings.TrimPrefix(cleanRel, "/")
	if prefix == "" {
		return "/" + cleanRel
	}
	return "/" + strings.Trim(prefix, "/") + "/" + cleanRel
}

func stableID(kind, relPath string) string {
	h := sha256.Sum256([]byte(kind + ":" + relPath))
	return hex.EncodeToString(h[:])
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
