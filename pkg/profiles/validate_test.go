package profiles

import "testing"

func TestValidateRequiresID(t *testing.T) {
	profile := &Profile{
		Name: "Device",
		Network: NetworkConfig{
			ServerIP: "192.168.77.1",
			CIDR:     "192.168.77.1/24",
		},
		Artifacts: Artifacts{HTTPFiles: []string{"file"}},
	}
	if err := Validate(profile); err == nil {
		t.Fatal("expected error for missing id")
	}
}
