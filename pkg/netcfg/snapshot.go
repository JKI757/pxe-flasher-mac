package netcfg

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

type Snapshot struct {
	Iface      string
	WasUp      bool
	DHCP       bool
	IPv4       []IPv4Addr
	CapturedAt time.Time
}

type IPv4Addr struct {
	IP   net.IP
	Mask net.IPMask
}

func SnapshotInterface(iface string) (*Snapshot, error) {
	if strings.TrimSpace(iface) == "" {
		return nil, fmt.Errorf("interface name required")
	}
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}
	output, err := runCommand("/sbin/ifconfig", iface)
	if err != nil {
		return nil, fmt.Errorf("ifconfig %s: %w", iface, err)
	}
	ipv4Addrs, err := parseIPv4Addrs(output)
	if err != nil {
		return nil, err
	}
	isDHCP := detectDHCP(iface)
	return &Snapshot{
		Iface:      iface,
		WasUp:      ni.Flags&net.FlagUp != 0,
		DHCP:       isDHCP,
		IPv4:       ipv4Addrs,
		CapturedAt: time.Now().UTC(),
	}, nil
}

func detectDHCP(iface string) bool {
	output, err := runCommand("/usr/sbin/ipconfig", "getpacket", iface)
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) != ""
}

func runCommand(path string, args ...string) (string, error) {
	cmd := exec.Command(path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", path, strings.Join(args, " "), err)
	}
	return string(out), nil
}

func parseIPv4Addrs(output string) ([]IPv4Addr, error) {
	var addrs []IPv4Addr
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for i := 0; i < len(fields); i++ {
			if fields[i] != "inet" {
				continue
			}
			if i+1 >= len(fields) {
				break
			}
			ip := net.ParseIP(fields[i+1])
			if ip == nil {
				break
			}
			ip = ip.To4()
			if ip == nil {
				break
			}
			mask := net.IPMask(nil)
			for j := i + 2; j < len(fields); j++ {
				if fields[j] == "netmask" && j+1 < len(fields) {
					mask = parseMask(fields[j+1])
					break
				}
			}
			addrs = append(addrs, IPv4Addr{IP: ip, Mask: mask})
			break
		}
	}
	return addrs, nil
}

func parseMask(value string) net.IPMask {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "0x") {
		parsed, err := parseHexMask(value)
		if err == nil {
			return parsed
		}
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	return net.IPv4Mask(ip[0], ip[1], ip[2], ip[3])
}

func parseHexMask(value string) (net.IPMask, error) {
	value = strings.TrimPrefix(value, "0x")
	if len(value) > 8 {
		return nil, fmt.Errorf("invalid hex mask")
	}
	for len(value) < 8 {
		value = "0" + value
	}
	var bytes [4]byte
	for i := 0; i < 4; i++ {
		part := value[i*2 : i*2+2]
		b, err := parseHexByte(part)
		if err != nil {
			return nil, err
		}
		bytes[i] = b
	}
	return net.IPv4Mask(bytes[0], bytes[1], bytes[2], bytes[3]), nil
}

func parseHexByte(value string) (byte, error) {
	var out byte
	for i := 0; i < len(value); i++ {
		out <<= 4
		switch {
		case value[i] >= '0' && value[i] <= '9':
			out |= value[i] - '0'
		case value[i] >= 'a' && value[i] <= 'f':
			out |= value[i] - 'a' + 10
		case value[i] >= 'A' && value[i] <= 'F':
			out |= value[i] - 'A' + 10
		default:
			return 0, fmt.Errorf("invalid hex byte")
		}
	}
	return out, nil
}
