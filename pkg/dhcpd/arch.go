package dhcpd

import (
	"strconv"

	"github.com/insomniacslk/dhcp/iana"

	"netboot-flasher/pkg/profiles"
)

var archKeyMap = map[iana.Arch][]string{
	iana.EFI_X86_64:      {"UEFI_X86_64", "EFI_X86_64", "x86_64"},
	iana.EFI_X86_64_HTTP: {"UEFI_X86_64_HTTP", "EFI_X86_64_HTTP"},
	iana.EFI_IA32:        {"UEFI_X86", "EFI_IA32", "x86"},
	iana.INTEL_X86PC:     {"BIOS_X86", "INTEL_X86PC", "x86"},
	iana.EFI_ARM64:       {"UEFI_ARM64", "EFI_ARM64"},
	iana.EFI_ARM64_HTTP:  {"UEFI_ARM64_HTTP", "EFI_ARM64_HTTP"},
}

func SelectArchEntry(archs []iana.Arch, archMap map[string]profiles.ArchEntry) (profiles.ArchEntry, bool) {
	for _, arch := range archs {
		keys := archKeys(arch)
		for _, key := range keys {
			if entry, ok := archMap[key]; ok {
				return entry, true
			}
		}
	}
	return profiles.ArchEntry{}, false
}

func archKeys(arch iana.Arch) []string {
	keys := append([]string{}, archKeyMap[arch]...)
	keys = append(keys, strconv.Itoa(int(arch)))
	keys = append(keys, arch.String())
	return keys
}
