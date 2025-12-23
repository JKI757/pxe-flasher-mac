package dhcpd

import (
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"netboot-flasher/pkg/profiles"
)

type Matcher struct {
	vendorPrefixes []string
	userPrefixes   []string
	macAllow       map[string]struct{}
	macDeny        map[string]struct{}
}

func NewMatcher(match profiles.DHCPMatch) Matcher {
	matcher := Matcher{
		vendorPrefixes: normalizePrefixes(match.VendorClassPrefixes),
		userPrefixes:   normalizePrefixes(match.UserClassPrefixes),
		macAllow:       make(map[string]struct{}),
		macDeny:        make(map[string]struct{}),
	}
	for _, mac := range match.MACAllowlist {
		mac = strings.ToUpper(strings.TrimSpace(mac))
		if mac != "" {
			matcher.macAllow[mac] = struct{}{}
		}
	}
	for _, mac := range match.MACDenylist {
		mac = strings.ToUpper(strings.TrimSpace(mac))
		if mac != "" {
			matcher.macDeny[mac] = struct{}{}
		}
	}
	return matcher
}

func (m Matcher) Allows(msg *dhcpv4.DHCPv4) bool {
	if msg == nil {
		return false
	}
	mac := normalizeMAC(msg.ClientHWAddr)
	if mac != "" {
		if _, denied := m.macDeny[mac]; denied {
			return false
		}
		if len(m.macAllow) > 0 {
			if _, ok := m.macAllow[mac]; !ok {
				return false
			}
		}
	}
	if len(m.vendorPrefixes) > 0 {
		classID := msg.ClassIdentifier()
		if !hasPrefix(classID, m.vendorPrefixes) {
			return false
		}
	}
	if len(m.userPrefixes) > 0 {
		userClasses := msg.UserClass()
		if !anyPrefix(userClasses, m.userPrefixes) {
			return false
		}
	}
	return true
}

func normalizePrefixes(values []string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func anyPrefix(values []string, prefixes []string) bool {
	for _, value := range values {
		if hasPrefix(value, prefixes) {
			return true
		}
	}
	return false
}
