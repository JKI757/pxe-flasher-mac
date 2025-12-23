package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netboot-flasher/pkg/dhcpd"
	"netboot-flasher/pkg/httpd"
	"netboot-flasher/pkg/logging"
	"netboot-flasher/pkg/netcfg"
	"netboot-flasher/pkg/profiles"
	"netboot-flasher/pkg/sessions"
	"netboot-flasher/pkg/tftpd"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("empty value")
	}
	*s = append(*s, value)
	return nil
}

func main() {
	if err := run(); err != nil {
		exitErr(err.Error())
	}
}

func run() error {
	var profilePath string
	var profileDir string
	var bindAddr string
	var ifaceName string
	var dhcpPort string
	var tftpPort string
	var enableDHCP bool
	var enableTFTP bool
	var runRoot string
	var roots stringList

	flag.StringVar(&profilePath, "profile", "", "Path to profile YAML")
	flag.StringVar(&profileDir, "profile-dir", "profiles", "Directory containing profile YAMLs")
	flag.StringVar(&bindAddr, "bind", "127.0.0.1:8080", "HTTP bind address")
	flag.StringVar(&ifaceName, "iface", "", "Interface name for DHCP/TFTP (optional)")
	flag.StringVar(&dhcpPort, "dhcp-port", "6767", "DHCP server port (67 requires root)")
	flag.StringVar(&tftpPort, "tftp-port", "6969", "TFTP server port (69 requires root)")
	flag.BoolVar(&enableDHCP, "enable-dhcp", false, "Start DHCP server (requires -iface)")
	flag.BoolVar(&enableTFTP, "enable-tftp", false, "Start TFTP server (requires -iface)")
	flag.StringVar(&runRoot, "run-root", "runs", "Runs directory")
	flag.Var(&roots, "artifact-root", "Artifact root (repeatable)")
	flag.Parse()

	if profilePath == "" {
		selected, err := selectProfile(profileDir)
		if err != nil {
			return err
		}
		profilePath = selected
	}
	if len(roots) == 0 {
		selected, err := selectArtifactRoots("artifacts")
		if err != nil {
			return err
		}
		roots = selected
	}
	if err := validateArtifactRoots(roots); err != nil {
		return err
	}

	profile, err := profiles.LoadProfile(profilePath)
	if err != nil {
		return err
	}
	if err := profiles.Validate(profile); err != nil {
		return err
	}

	manifest, err := profiles.ResolveArtifacts(profile, roots)
	if err != nil {
		return err
	}

	if enableDHCP || enableTFTP {
		if ifaceName == "" {
			return fmt.Errorf("-iface is required when enabling DHCP/TFTP")
		}
	}

	runID := time.Now().UTC().Format("20060102-150405")
	runDir := filepath.Join(runRoot, runID)
	logDir := filepath.Join(runDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("create run dir: %v", err)
	}

	manifestPath := filepath.Join(runDir, "manifest.json")
	if err := profiles.WriteManifest(manifestPath, manifest); err != nil {
		return err
	}

	logFile, err := os.OpenFile(filepath.Join(logDir, "http.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log: %v", err)
	}
	logger := logging.New(io.MultiWriter(os.Stdout, logFile))

	store, err := sessions.NewStore(runID, runDir)
	if err != nil {
		_ = logFile.Close()
		return err
	}

	var dhcpServer *dhcpd.Server
	var tftpServer *tftpd.Server
	var netSnapshot *netcfg.Snapshot
	var server *httpd.Server

	cleanup := func() {
		if tftpServer != nil {
			tftpServer.Shutdown()
		}
		if dhcpServer != nil {
			_ = dhcpServer.Shutdown()
		}
		if netSnapshot != nil {
			_ = netcfg.Restore(netSnapshot)
		}
		if server != nil {
			_ = server.Shutdown(5 * time.Second)
		}
		if err := store.Close(); err != nil {
			logger.Errorf("close store: %v", err)
		}
		if err := logFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close log: %v\n", err)
		}
	}
	defer cleanup()

	var ifaceIP string
	if enableDHCP || enableTFTP {
		netSnapshot, err = netcfg.ApplyStaticIPv4(ifaceName, profile.Network.ServerIP, profile.Network.CIDR)
		if err != nil {
			return err
		}
		ifaceIP = profile.Network.ServerIP
		host, port, err := net.SplitHostPort(bindAddr)
		if err != nil {
			return fmt.Errorf("bind address must be host:port: %w", err)
		}
		if host != ifaceIP {
			bindAddr = net.JoinHostPort(ifaceIP, port)
			logger.Infof("bind address updated to %s", bindAddr)
		}
	}

	if enableDHCP {
		dhcpPort, err = normalizePort(dhcpPort)
		if err != nil {
			return fmt.Errorf("dhcp port: %v", err)
		}
		dhcpServer, err = newDHCPServer(profile, ifaceName, ifaceIP, dhcpPort, logger, store)
		if err != nil {
			return err
		}
		go func() {
			_ = dhcpServer.Serve()
		}()
	}
	if enableTFTP && manifestHasKind(manifest, "tftp") {
		tftpPort, err = normalizePort(tftpPort)
		if err != nil {
			return fmt.Errorf("tftp port: %v", err)
		}
		tftpBind := net.JoinHostPort(ifaceIP, tftpPort)
		tftpServer, err = tftpd.NewServer(tftpd.Config{
			BindAddr: tftpBind,
			Manifest: manifest,
			Logger:   logger,
			Sessions: store,
		})
		if err != nil {
			return err
		}
		go func() {
			_ = tftpServer.ListenAndServe()
		}()
	}

	server, err = httpd.NewServer(httpd.Config{
		BindAddr: bindAddr,
		Manifest: manifest,
		Sessions: store,
		Logger:   logger,
	})
	if err != nil {
		return err
	}

	logger.Infof("run %s manifest at %s", runID, manifestPath)
	logger.Infof("listening on %s", bindAddr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigs:
		logger.Infof("received %s, shutting down", sig)
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %v", err)
		}
	}
	return nil
}

func exitErr(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func selectProfile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if isInteractive() {
			return promptForProfilePath(fmt.Sprintf("profile-dir %q not readable", dir))
		}
		return "", fmt.Errorf("no profile provided and profile-dir %q not readable: %w", dir, err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, name))
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no profiles found in %s; pass -profile or add a YAML file", dir)
	}
	sort.Strings(files)
	if len(files) == 1 {
		fmt.Fprintf(os.Stdout, "using profile %s\n", filepath.Base(files[0]))
		return files[0], nil
	}
	if !isInteractive() {
		return "", fmt.Errorf("multiple profiles in %s; pass -profile or run interactively", dir)
	}
	fmt.Fprintln(os.Stdout, "Select a profile:")
	for i, file := range files {
		fmt.Fprintf(os.Stdout, "  [%d] %s\n", i+1, filepath.Base(file))
	}
	fmt.Fprintf(os.Stdout, "Enter number (1-%d): ", len(files))
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("profile selection aborted")
	}
	choice := strings.TrimSpace(scanner.Text())
	index, err := strconv.Atoi(choice)
	if err != nil || index < 1 || index > len(files) {
		return "", fmt.Errorf("invalid selection")
	}
	return files[index-1], nil
}

func isInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func normalizePort(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("port required")
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %q", value)
	}
	return strconv.Itoa(port), nil
}

func newDHCPServer(profile *profiles.Profile, ifaceName string, ifaceIP string, port string, logger *logging.Logger, store *sessions.Store) (*dhcpd.Server, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile required")
	}
	if ifaceName == "" || ifaceIP == "" {
		return nil, fmt.Errorf("interface selection required for DHCP")
	}
	serverIP := net.ParseIP(profile.Network.ServerIP)
	if serverIP == nil {
		return nil, fmt.Errorf("invalid profile server_ip")
	}
	serverIP = serverIP.To4()
	if serverIP == nil {
		return nil, fmt.Errorf("profile server_ip must be IPv4")
	}
	if serverIP.String() != ifaceIP {
		return nil, fmt.Errorf("profile server_ip (%s) must match interface (%s)", serverIP, ifaceIP)
	}
	poolStart := net.ParseIP(profile.Network.PoolStart)
	poolEnd := net.ParseIP(profile.Network.PoolEnd)
	if poolStart == nil || poolEnd == nil {
		return nil, fmt.Errorf("profile pool_start/pool_end required for DHCP")
	}
	poolStart = poolStart.To4()
	poolEnd = poolEnd.To4()
	if poolStart == nil || poolEnd == nil {
		return nil, fmt.Errorf("profile pool_start/pool_end must be IPv4")
	}
	bindAddr := net.JoinHostPort(ifaceIP, port)
	return dhcpd.NewServer(dhcpd.Config{
		InterfaceName: ifaceName,
		BindAddr:      bindAddr,
		ServerIP:      serverIP,
		PoolStart:     poolStart,
		PoolEnd:       poolEnd,
		LeaseSeconds:  profile.Network.LeaseSeconds,
		NetworkCIDR:   profile.Network.CIDR,
		Boot:          profile.Boot,
		DHCP:          profile.DHCP,
		HTTPRoot:      profile.Boot.HTTPRoot,
		Logger:        logger,
		Sessions:      store,
	})
}

func manifestHasKind(manifest *profiles.Manifest, kind string) bool {
	if manifest == nil {
		return false
	}
	for _, file := range manifest.Files {
		if file.Kind == kind {
			return true
		}
	}
	return false
}

func ipv4ForInterface(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("read interface addresses: %w", err)
	}
	ip := pickIPv4(addrs)
	if ip == "" {
		return "", fmt.Errorf("no IPv4 address on interface %s", name)
	}
	return ip, nil
}

func pickIPv4(addrs []net.Addr) string {
	var fallback string
	for _, addr := range addrs {
		ip := extractIPv4(addr)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.IsLoopback() {
			if fallback == "" {
				fallback = ip
			}
			continue
		}
		if parsed.IsLinkLocalUnicast() {
			if fallback == "" {
				fallback = ip
			}
			continue
		}
		return ip
	}
	return fallback
}

func extractIPv4(addr net.Addr) string {
	switch v := addr.(type) {
	case *net.IPNet:
		if ip := v.IP.To4(); ip != nil {
			return ip.String()
		}
	case *net.IPAddr:
		if ip := v.IP.To4(); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func promptForProfilePath(reason string) (string, error) {
	fmt.Fprintf(os.Stdout, "Select a profile (%s). Enter path to YAML: ", reason)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("profile selection aborted")
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return "", fmt.Errorf("profile path required")
	}
	info, err := os.Stat(input)
	if err != nil {
		return "", fmt.Errorf("profile path not found: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("profile path is a directory")
	}
	ext := strings.ToLower(filepath.Ext(input))
	if ext != ".yaml" && ext != ".yml" {
		return "", fmt.Errorf("profile must be .yaml or .yml")
	}
	return input, nil
}

func selectArtifactRoots(defaultDir string) ([]string, error) {
	defaultDir = strings.TrimSpace(defaultDir)
	if defaultDir == "" {
		defaultDir = "artifacts"
	}
	defaultExists := dirExists(defaultDir)
	if !isInteractive() {
		if defaultExists {
			return []string{defaultDir}, nil
		}
		return nil, fmt.Errorf("no artifact-root provided and non-interactive; pass -artifact-root")
	}
	prompt := "Enter artifact root(s) (comma separated)"
	if defaultExists {
		prompt += fmt.Sprintf(" [default: %s]", defaultDir)
	}
	fmt.Fprint(os.Stdout, prompt+": ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("artifact root selection aborted")
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		if defaultExists {
			return []string{defaultDir}, nil
		}
		return nil, fmt.Errorf("artifact root required")
	}
	parts := strings.Split(input, ",")
	var roots []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		roots = append(roots, part)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("artifact root required")
	}
	return roots, nil
}

func validateArtifactRoots(roots []string) error {
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return fmt.Errorf("artifact root %s not found: %w", root, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("artifact root %s is not a directory", root)
		}
	}
	return nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
