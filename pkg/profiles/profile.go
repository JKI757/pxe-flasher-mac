package profiles

type Profile struct {
	ID          string        `yaml:"id"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Network     NetworkConfig `yaml:"network"`
	DHCP        DHCPConfig    `yaml:"dhcp"`
	Boot        BootConfig    `yaml:"boot"`
	Artifacts   Artifacts     `yaml:"artifacts"`
	Imaging     Imaging       `yaml:"imaging"`
	Postboot    Postboot      `yaml:"postboot"`
}

type NetworkConfig struct {
	ServerIP     string `yaml:"server_ip"`
	CIDR         string `yaml:"cidr"`
	PoolStart    string `yaml:"pool_start"`
	PoolEnd      string `yaml:"pool_end"`
	LeaseSeconds int    `yaml:"lease_seconds"`
}

type DHCPConfig struct {
	Match   DHCPMatch            `yaml:"match"`
	ArchMap map[string]ArchEntry `yaml:"arch_map"`
}

type DHCPMatch struct {
	VendorClassPrefixes []string `yaml:"vendor_class_prefixes"`
	UserClassPrefixes   []string `yaml:"user_class_prefixes"`
	MACAllowlist        []string `yaml:"mac_allowlist"`
	MACDenylist         []string `yaml:"mac_denylist"`
}

type ArchEntry struct {
	BootFilename string `yaml:"boot_filename"`
}

type BootConfig struct {
	Mode     string                `yaml:"mode"`
	TFTPRoot string                `yaml:"tftp_root"`
	HTTPRoot string                `yaml:"http_root"`
	PerMAC   map[string]BootPerMAC `yaml:"per_mac"`
}

type BootPerMAC struct {
	BootFilename string   `yaml:"boot_filename"`
	HTTPTags     []string `yaml:"http_tags"`
}

type Artifacts struct {
	TFTPFiles []string `yaml:"tftp_files"`
	HTTPFiles []string `yaml:"http_files"`
}

type Imaging struct {
	Mode           string         `yaml:"mode"`
	NetworkInstall NetworkInstall `yaml:"network_install"`
	FullImagePush  FullImagePush  `yaml:"full_image_push"`
}

type NetworkInstall struct {
	Kernel          string `yaml:"kernel"`
	Initrd          string `yaml:"initrd"`
	CmdlineTemplate string `yaml:"cmdline_template"`
}

type FullImagePush struct {
	Method string      `yaml:"method"`
	Image  string      `yaml:"image"`
	Verify ImageVerify `yaml:"verify"`
}

type ImageVerify struct {
	SHA256 string `yaml:"sha256"`
}

type Postboot struct {
	WaitForSSH bool `yaml:"wait_for_ssh"`
}
