package dhcpd

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"

	"netboot-flasher/pkg/logging"
	"netboot-flasher/pkg/profiles"
	"netboot-flasher/pkg/sessions"
)

type Config struct {
	InterfaceName string
	BindAddr      string
	ServerIP      net.IP
	PoolStart     net.IP
	PoolEnd       net.IP
	LeaseSeconds  int
	NetworkCIDR   string
	Boot          profiles.BootConfig
	DHCP          profiles.DHCPConfig
	HTTPRoot      string
	Logger        *logging.Logger
	Sessions      *sessions.Store
}

type Server struct {
	cfg       Config
	server    *server4.Server
	leases    map[string]lease
	leasesMu  sync.Mutex
	matcher   Matcher
	leaseDur  time.Duration
	netmask   net.IPMask
	serverIP  net.IP
	poolStart net.IP
	poolEnd   net.IP
	logger    *logging.Logger
	sessions  *sessions.Store
}

type lease struct {
	IP     net.IP
	Expiry time.Time
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.InterfaceName == "" {
		return nil, fmt.Errorf("interface name required")
	}
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("bind address required")
	}
	serverIP := cfg.ServerIP
	if serverIP == nil {
		return nil, fmt.Errorf("server IP required")
	}
	serverIP = serverIP.To4()
	if serverIP == nil {
		return nil, fmt.Errorf("server IP must be IPv4")
	}
	poolStart := cfg.PoolStart
	poolEnd := cfg.PoolEnd
	if poolStart == nil || poolEnd == nil {
		return nil, fmt.Errorf("pool start/end required")
	}
	poolStart = poolStart.To4()
	poolEnd = poolEnd.To4()
	if poolStart == nil || poolEnd == nil {
		return nil, fmt.Errorf("pool start/end must be IPv4")
	}
	mask, err := parseCIDRMask(cfg.NetworkCIDR)
	if err != nil {
		return nil, err
	}
	leaseSeconds := cfg.LeaseSeconds
	if leaseSeconds <= 0 {
		leaseSeconds = 600
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve bind addr: %w", err)
	}

	s := &Server{
		cfg:       cfg,
		leases:    make(map[string]lease),
		matcher:   NewMatcher(cfg.DHCP.Match),
		leaseDur:  time.Duration(leaseSeconds) * time.Second,
		netmask:   mask,
		serverIP:  serverIP,
		poolStart: poolStart,
		poolEnd:   poolEnd,
		logger:    cfg.Logger,
		sessions:  cfg.Sessions,
	}

	server, err := server4.NewServer(cfg.InterfaceName, addr, s.handle, server4.WithLogger(dhcpLogger{logger: cfg.Logger}))
	if err != nil {
		return nil, err
	}
	s.server = server
	return s, nil
}

func (s *Server) Serve() error {
	if s == nil || s.server == nil {
		return fmt.Errorf("dhcp server not initialized")
	}
	return s.server.Serve()
}

func (s *Server) Shutdown() error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Close()
}

func (s *Server) handle(conn net.PacketConn, peer net.Addr, msg *dhcpv4.DHCPv4) {
	if msg == nil {
		return
	}
	if !s.matcher.Allows(msg) {
		return
	}

	mac := normalizeMAC(msg.ClientHWAddr)
	switch msg.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		if s.sessions != nil {
			_ = s.sessions.Append(sessions.SessionEvent{
				Type: sessions.EventDHCPDiscover,
				MAC:  mac,
			})
		}
		reply, assigned, err := s.buildReply(msg, dhcpv4.MessageTypeOffer)
		if err != nil {
			s.logf("dhcp offer error: %v", err)
			return
		}
		s.sendReply(conn, peer, reply)
		s.logf("dhcp offer %s -> %s", mac, assigned)
	case dhcpv4.MessageTypeRequest:
		reply, assigned, err := s.buildReply(msg, dhcpv4.MessageTypeAck)
		if err != nil {
			s.logf("dhcp ack error: %v", err)
			return
		}
		s.sendReply(conn, peer, reply)
		s.logf("dhcp ack %s -> %s", mac, assigned)
		if s.sessions != nil {
			_ = s.sessions.Append(sessions.SessionEvent{
				Type: sessions.EventDHCPAck,
				MAC:  mac,
				IP:   assigned,
			})
		}
	default:
		// ignore
	}
}

func (s *Server) buildReply(msg *dhcpv4.DHCPv4, messageType dhcpv4.MessageType) (*dhcpv4.DHCPv4, string, error) {
	reply, err := dhcpv4.NewReplyFromRequest(msg)
	if err != nil {
		return nil, "", err
	}
	assigned, err := s.allocateIP(msg.ClientHWAddr, msg.RequestedIPAddress())
	if err != nil {
		return nil, "", err
	}
	reply.YourIPAddr = assigned
	reply.ServerIPAddr = s.serverIP
	reply.UpdateOption(dhcpv4.OptMessageType(messageType))
	reply.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
	if s.netmask != nil {
		reply.UpdateOption(dhcpv4.OptSubnetMask(s.netmask))
	}
	reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.leaseDur))

	bootFilename := s.selectBootFilename(msg)
	if bootFilename != "" {
		reply.BootFileName = bootFilename
		reply.UpdateOption(dhcpv4.OptBootFileName(bootFilename))
		reply.UpdateOption(dhcpv4.OptTFTPServerName(s.serverIP.String()))
	}
	return reply, assigned.String(), nil
}

func (s *Server) selectBootFilename(msg *dhcpv4.DHCPv4) string {
	mac := normalizeMAC(msg.ClientHWAddr)
	if mac != "" {
		if per, ok := s.cfg.Boot.PerMAC[mac]; ok && strings.TrimSpace(per.BootFilename) != "" {
			return s.resolveBootFilename(per.BootFilename)
		}
	}
	entry, ok := SelectArchEntry(msg.ClientArch(), s.cfg.DHCP.ArchMap)
	if ok && strings.TrimSpace(entry.BootFilename) != "" {
		return s.resolveBootFilename(entry.BootFilename)
	}
	if entry, ok := s.cfg.DHCP.ArchMap["default"]; ok && strings.TrimSpace(entry.BootFilename) != "" {
		return s.resolveBootFilename(entry.BootFilename)
	}
	return ""
}

func (s *Server) resolveBootFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	mode := strings.TrimSpace(s.cfg.Boot.Mode)
	if mode == "" {
		mode = "tftp"
	}
	if mode == "httpboot" {
		if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
			return name
		}
		prefix := strings.Trim(s.cfg.Boot.HTTPRoot, "/")
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		return "http://" + s.serverIP.String() + "/" + path
	}
	return name
}

func (s *Server) sendReply(conn net.PacketConn, peer net.Addr, reply *dhcpv4.DHCPv4) {
	if reply == nil {
		return
	}
	if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
		s.logf("dhcp send error: %v", err)
	}
}

func (s *Server) allocateIP(hw net.HardwareAddr, requested net.IP) (net.IP, error) {
	mac := normalizeMAC(hw)
	if mac == "" {
		return nil, fmt.Errorf("missing MAC")
	}
	now := time.Now()
	s.leasesMu.Lock()
	defer s.leasesMu.Unlock()

	if lease, ok := s.leases[mac]; ok && lease.Expiry.After(now) {
		return lease.IP, nil
	}

	if requested != nil {
		requested = requested.To4()
		if requested != nil && s.inPool(requested) && s.isFree(requested, mac, now) {
			return s.storeLease(mac, requested, now), nil
		}
	}

	start := ipToUint32(s.poolStart)
	end := ipToUint32(s.poolEnd)
	for ip := start; ip <= end; ip++ {
		candidate := uint32ToIP(ip)
		if candidate.Equal(s.serverIP) {
			continue
		}
		if s.isFree(candidate, mac, now) {
			return s.storeLease(mac, candidate, now), nil
		}
	}
	return nil, fmt.Errorf("no free lease available")
}

func (s *Server) isFree(ip net.IP, mac string, now time.Time) bool {
	for key, lease := range s.leases {
		if lease.Expiry.Before(now) {
			delete(s.leases, key)
			continue
		}
		if lease.IP.Equal(ip) && key != mac {
			return false
		}
	}
	return true
}

func (s *Server) storeLease(mac string, ip net.IP, now time.Time) net.IP {
	lease := lease{IP: ip, Expiry: now.Add(s.leaseDur)}
	s.leases[mac] = lease
	return lease.IP
}

func (s *Server) inPool(ip net.IP) bool {
	if ip == nil {
		return false
	}
	value := ipToUint32(ip)
	return value >= ipToUint32(s.poolStart) && value <= ipToUint32(s.poolEnd)
}

func (s *Server) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Infof(format, args...)
	}
}

type dhcpLogger struct {
	logger *logging.Logger
}

func (d dhcpLogger) PrintMessage(prefix string, message *dhcpv4.DHCPv4) {
	if d.logger == nil || message == nil {
		return
	}
	d.logger.Infof("%s %s", prefix, message.Summary())
}

func (d dhcpLogger) Printf(format string, v ...interface{}) {
	if d.logger == nil {
		return
	}
	d.logger.Infof(format, v...)
}

func parseCIDRMask(cidr string) (net.IPMask, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, nil
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %q", cidr)
	}
	return network.Mask, nil
}

func normalizeMAC(hw net.HardwareAddr) string {
	if hw == nil {
		return ""
	}
	return strings.ToUpper(hw.String())
}

func ipToUint32(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToIP(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}
