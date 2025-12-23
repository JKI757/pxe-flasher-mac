package profiles

import (
	"path"
	"path/filepath"
	"strings"
)

func isSafeRelPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	if filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return false
		}
	}
	return true
}

func cleanURLPrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", nil
	}
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return "", nil
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == ".." || part == "." || part == "" {
			return "", errInvalidPrefix(prefix)
		}
	}
	return strings.TrimPrefix(path.Clean("/"+prefix), "/"), nil
}

func errInvalidPrefix(prefix string) error {
	return &invalidPrefixError{prefix: prefix}
}

type invalidPrefixError struct {
	prefix string
}

func (e *invalidPrefixError) Error() string {
	return "invalid prefix: " + e.prefix
}
