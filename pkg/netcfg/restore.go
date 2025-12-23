package netcfg

import (
	"fmt"
	"strings"
)

func Restore(snap *Snapshot) error {
	if snap == nil {
		return nil
	}
	iface := strings.TrimSpace(snap.Iface)
	if iface == "" {
		return fmt.Errorf("snapshot missing interface")
	}
	if snap.DHCP {
		_, err := runCommand("/usr/sbin/ipconfig", "set", iface, "DHCP")
		return err
	}
	if len(snap.IPv4) == 0 {
		return fmt.Errorf("no IPv4 address to restore")
	}
	addr := snap.IPv4[0]
	mask := maskToString(addr.Mask)
	if mask == "" {
		return fmt.Errorf("invalid netmask in snapshot")
	}
	_, err := runCommand("/sbin/ifconfig", iface, "inet", addr.IP.String(), "netmask", mask, "up")
	return err
}
