package netcfg

import (
	"fmt"
	"net"
	"strings"
)

func ApplyStaticIPv4(iface string, serverIP string, cidr string) (*Snapshot, error) {
	snap, err := SnapshotInterface(iface)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(serverIP))
	if ip == nil {
		return nil, fmt.Errorf("invalid server IP %q", serverIP)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("server IP must be IPv4")
	}
	mask, err := maskFromCIDR(cidr)
	if err != nil {
		return nil, err
	}
	maskString := maskToString(mask)
	if maskString == "" {
		return nil, fmt.Errorf("invalid netmask")
	}
	_, err = runCommand("/sbin/ifconfig", iface, "inet", ip.String(), "netmask", maskString, "up")
	if err != nil {
		return nil, err
	}
	return snap, nil
}

func maskFromCIDR(cidr string) (net.IPMask, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, fmt.Errorf("cidr required")
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %q", cidr)
	}
	return network.Mask, nil
}

func maskToString(mask net.IPMask) string {
	if len(mask) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
