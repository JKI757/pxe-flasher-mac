package profiles

import (
	"fmt"
	"strings"
)

func Validate(p *Profile) error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("profile id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("profile name is required")
	}
	if strings.TrimSpace(p.Network.ServerIP) == "" {
		return fmt.Errorf("network.server_ip is required")
	}
	if strings.TrimSpace(p.Network.CIDR) == "" {
		return fmt.Errorf("network.cidr is required")
	}
	mode := strings.TrimSpace(p.Boot.Mode)
	if mode == "" {
		mode = "tftp"
	}
	switch mode {
	case "tftp", "httpboot":
		// ok
	default:
		return fmt.Errorf("boot.mode must be tftp or httpboot")
	}
	if len(p.Artifacts.TFTPFiles) == 0 && len(p.Artifacts.HTTPFiles) == 0 {
		return fmt.Errorf("artifacts.tftp_files or artifacts.http_files must be set")
	}
	if err := validateArtifactList(p.Artifacts.TFTPFiles); err != nil {
		return fmt.Errorf("artifacts.tftp_files: %w", err)
	}
	if err := validateArtifactList(p.Artifacts.HTTPFiles); err != nil {
		return fmt.Errorf("artifacts.http_files: %w", err)
	}
	if _, err := cleanURLPrefix(p.Boot.HTTPRoot); err != nil {
		return fmt.Errorf("boot.http_root: %w", err)
	}
	if _, err := cleanURLPrefix(p.Boot.TFTPRoot); err != nil {
		return fmt.Errorf("boot.tftp_root: %w", err)
	}
	return nil
}

func validateArtifactList(items []string) error {
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("contains empty path")
		}
		if !isSafeRelPath(item) {
			return fmt.Errorf("invalid path: %q", item)
		}
	}
	return nil
}
