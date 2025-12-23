package profiles

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile yaml: %w", err)
	}
	return &p, nil
}
