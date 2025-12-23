package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"netboot-flasher/pkg/dhcpd"
	"netboot-flasher/pkg/httpd"
	"netboot-flasher/pkg/logging"
	"netboot-flasher/pkg/netcfg"
	"netboot-flasher/pkg/profiles"
	"netboot-flasher/pkg/sessions"
	"netboot-flasher/pkg/tftpd"
)

type profileOption struct {
	Label string
	Path  string
}

type ifaceOption struct {
	Label string
	Name  string
	IP    string
}

type runHandle struct {
	server    *httpd.Server
	dhcp      *dhcpd.Server
	tftp      *tftpd.Server
	network   *netcfg.Snapshot
	flashOn   bool
	store     *sessions.Store
	logFile   *os.File
	logPath   string
	eventPath string
	runID     string
	runDir    string
	ifaceName string
	ifaceIP   string
}

func (r *runHandle) Stop() error {
	if r == nil {
		return nil
	}
	var errOut error
	if r.dhcp != nil {
		if err := r.dhcp.Shutdown(); err != nil && errOut == nil {
			errOut = err
		}
	}
	if r.tftp != nil {
		r.tftp.Shutdown()
	}
	if r.network != nil {
		if err := netcfg.Restore(r.network); err != nil && errOut == nil {
			errOut = err
		}
	}
	if r.server != nil {
		if err := r.server.Shutdown(5 * time.Second); err != nil {
			errOut = err
		}
	}
	if r.store != nil {
		if err := r.store.Close(); err != nil && errOut == nil {
			errOut = err
		}
	}
	if r.logFile != nil {
		if err := r.logFile.Close(); err != nil && errOut == nil {
			errOut = err
		}
	}
	return errOut
}

func main() {
	a := app.New()
	w := a.NewWindow("Netboot Flasher (HTTP slice)")

	status := widget.NewLabel("Status: idle")
	runDirLabel := widget.NewLabel("Run dir: -")
	networkStatus := widget.NewLabel("Network: idle")
	dhcpStatus := widget.NewLabel("DHCP: off")
	tftpStatus := widget.NewLabel("TFTP: off")

	ifaceSelect := widget.NewSelect([]string{}, func(string) {})
	ifaceSelect.PlaceHolder = "Select interface"
	ifaceName := ""
	ifaceIP := ""
	ifaceMap := map[string]ifaceOption{}

	profileSelect := widget.NewSelect([]string{}, func(string) {})
	profileSelect.PlaceHolder = "Select a profile"
	profilePath := ""
	profileMap := map[string]string{}

	artifactRoots := []string{}
	selectedArtifact := -1
	artifactList := widget.NewList(
		func() int { return len(artifactRoots) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i int, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(artifactRoots[i])
		},
	)
	artifactList.OnSelected = func(id int) {
		selectedArtifact = id
	}

	bindEntry := widget.NewEntry()
	bindEntry.SetText("127.0.0.1:8080")
	runRootEntry := widget.NewEntry()
	runRootEntry.SetText("runs")
	dhcpPortEntry := widget.NewEntry()
	dhcpPortEntry.SetText("6767")
	tftpPortEntry := widget.NewEntry()
	tftpPortEntry.SetText("6969")
	enableFlashServices := widget.NewCheck("Enable DHCP/TFTP", func(bool) {})

	logFilter := widget.NewEntry()
	logFilter.SetPlaceHolder("Filter logs (case-insensitive)")
	logView := widget.NewMultiLineEntry()
	logView.Disable()
	logView.Wrapping = fyne.TextWrapWord
	logView.SetMinRowsVisible(8)

	events := []sessions.SessionEvent{}
	eventsList := widget.NewList(
		func() int { return len(events) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i int, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(formatEvent(events[i]))
		},
	)

	clients := []clientRow{}
	clientsTable := widget.NewTable(
		func() (int, int) { return len(clients) + 1, 3 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			if id.Row == 0 {
				switch id.Col {
				case 0:
					label.SetText("MAC")
				case 1:
					label.SetText("IP")
				case 2:
					label.SetText("Last Event")
				default:
					label.SetText("")
				}
				return
			}
			row := clients[id.Row-1]
			switch id.Col {
			case 0:
				label.SetText(row.MAC)
			case 1:
				label.SetText(row.IP)
			case 2:
				label.SetText(row.LastEvent)
			default:
				label.SetText("")
			}
		},
	)
	clientsTable.SetColumnWidth(0, 180)
	clientsTable.SetColumnWidth(1, 140)
	clientsTable.SetColumnWidth(2, 420)

	var mu sync.Mutex
	var refreshMu sync.Mutex
	var current *runHandle

	setRunning := func(handle *runHandle) {
		current = handle
		if handle == nil {
			status.SetText("Status: idle")
			runDirLabel.SetText("Run dir: -")
			networkStatus.SetText("Network: idle")
			dhcpStatus.SetText("DHCP: off")
			tftpStatus.SetText("TFTP: off")
			logView.SetText("")
			events = nil
			eventsList.Refresh()
			clients = nil
			clientsTable.Refresh()
			return
		}
		status.SetText(fmt.Sprintf("Status: running (%s on %s)", handle.runID, handle.ifaceName))
		runDirLabel.SetText("Run dir: " + handle.runDir)
		if handle.flashOn {
			networkStatus.SetText("Network: configured")
		} else {
			networkStatus.SetText("Network: unchanged")
		}
		if handle.dhcp != nil {
			dhcpStatus.SetText("DHCP: running")
		} else {
			dhcpStatus.SetText("DHCP: off")
		}
		if handle.tftp != nil {
			tftpStatus.SetText("TFTP: running")
		} else {
			tftpStatus.SetText("TFTP: off")
		}
	}

	startButton := widget.NewButton("Start", func() {})
	stopButton := widget.NewButton("Stop", func() {})
	stopButton.Disable()

	updateButtons := func(running bool) {
		if running {
			startButton.Disable()
			stopButton.Enable()
		} else {
			startButton.Enable()
			stopButton.Disable()
		}
	}

	showError := func(err error) {
		if err == nil {
			return
		}
		dialog.ShowError(err, w)
	}

	refreshRunViews := func() {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		mu.Lock()
		handle := current
		mu.Unlock()
		if handle == nil {
			logView.SetText("")
			events = nil
			eventsList.Refresh()
			clients = nil
			clientsTable.Refresh()
			return
		}
		logText, err := loadLog(handle.logPath, logFilter.Text)
		if err != nil {
			showError(err)
		} else {
			logView.SetText(logText)
		}
		loaded, err := loadEvents(handle.eventPath)
		if err != nil {
			showError(err)
		} else {
			events = loaded
			eventsList.Refresh()
			clients = buildClients(loaded)
			clientsTable.Refresh()
		}
	}

	refreshRunButton := widget.NewButton("Refresh", refreshRunViews)
	autoRefresh := widget.NewCheck("Auto-refresh", func(checked bool) {
		if checked {
			refreshRunViews()
		}
	})
	autoRefresh.SetChecked(true)
	stopRefresh := make(chan struct{})
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if autoRefresh.Checked {
					refreshRunViews()
				}
			case <-stopRefresh:
				return
			}
		}
	}()

	refreshInterfaces := func() {
		options, err := listInterfaces()
		if err != nil {
			ifaceSelect.Options = nil
			ifaceSelect.Refresh()
			ifaceMap = map[string]ifaceOption{}
			return
		}
		labels := make([]string, 0, len(options))
		ifaceMap = make(map[string]ifaceOption, len(options))
		for _, option := range options {
			labels = append(labels, option.Label)
			ifaceMap[option.Label] = option
		}
		ifaceSelect.Options = labels
		ifaceSelect.Refresh()
	}

	refreshProfiles := func() {
		options, err := listProfiles("profiles")
		if err != nil {
			profileSelect.Options = nil
			profileSelect.Refresh()
			profileMap = map[string]string{}
			return
		}
		labels := make([]string, 0, len(options))
		profileMap = make(map[string]string, len(options))
		for _, option := range options {
			labels = append(labels, option.Label)
			profileMap[option.Label] = option.Path
		}
		profileSelect.Options = labels
		profileSelect.Refresh()
	}

	profileSelect.OnChanged = func(label string) {
		profilePath = profileMap[label]
	}

	ifaceSelect.OnChanged = func(label string) {
		iface := ifaceMap[label]
		ifaceName = iface.Name
		ifaceIP = iface.IP
		if iface.IP != "" {
			bindEntry.SetText(net.JoinHostPort(iface.IP, resolvePort(bindEntry.Text)))
		}
	}

	refreshInterfaces()
	refreshProfiles()

	if dirExists("artifacts") {
		artifactRoots = append(artifactRoots, "artifacts")
		artifactList.Refresh()
	}

	addProfileButton := widget.NewButton("Browse...", func() {
		fileDialog := dialog.NewFileOpen(func(file fyne.URIReadCloser, err error) {
			if err != nil {
				showError(err)
				return
			}
			if file == nil {
				return
			}
			path := file.URI().Path()
			_ = file.Close()
			label := ensureProfileOption(profileSelect, profileMap, path)
			profilePath = path
			profileSelect.SetSelected(label)
		}, w)
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".yaml", ".yml"}))
		fileDialog.Show()
	})

	rescanButton := widget.NewButton("Rescan", func() {
		refreshProfiles()
	})

	rescanIfacesButton := widget.NewButton("Rescan", func() {
		refreshInterfaces()
	})

	addArtifactButton := widget.NewButton("Add...", func() {
		dialog.ShowFolderOpen(func(dir fyne.ListableURI, err error) {
			if err != nil {
				showError(err)
				return
			}
			if dir == nil {
				return
			}
			path := dir.Path()
			for _, existing := range artifactRoots {
				if existing == path {
					return
				}
			}
			artifactRoots = append(artifactRoots, path)
			artifactList.Refresh()
		}, w)
	})

	removeArtifactButton := widget.NewButton("Remove", func() {
		if selectedArtifact < 0 || selectedArtifact >= len(artifactRoots) {
			return
		}
		artifactRoots = append(artifactRoots[:selectedArtifact], artifactRoots[selectedArtifact+1:]...)
		selectedArtifact = -1
		artifactList.UnselectAll()
		artifactList.Refresh()
	})

	startButton.OnTapped = func() {
		mu.Lock()
		defer mu.Unlock()
		if current != nil {
			return
		}
		if strings.TrimSpace(ifaceName) == "" {
			showError(fmt.Errorf("select an interface"))
			return
		}
		if !enableFlashServices.Checked && strings.TrimSpace(ifaceIP) == "" {
			showError(fmt.Errorf("selected interface has no IPv4 address"))
			return
		}
		if strings.TrimSpace(profilePath) == "" {
			showError(fmt.Errorf("select a profile"))
			return
		}
		if len(artifactRoots) == 0 {
			showError(fmt.Errorf("add at least one artifact root"))
			return
		}
		if err := validateArtifactRoots(artifactRoots); err != nil {
			showError(err)
			return
		}
		handle, err := startRun(profilePath, artifactRoots, bindEntry.Text, runRootEntry.Text, dhcpPortEntry.Text, tftpPortEntry.Text, ifaceName, ifaceIP, enableFlashServices.Checked)
		if err != nil {
			showError(err)
			return
		}
		setRunning(handle)
		updateButtons(true)
		refreshRunViews()
		go func(local *runHandle) {
			err := local.server.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				showError(err)
				_ = local.Stop()
				mu.Lock()
				if current == local {
					setRunning(nil)
					updateButtons(false)
				}
				mu.Unlock()
			}
		}(handle)
	}

	stopButton.OnTapped = func() {
		mu.Lock()
		defer mu.Unlock()
		if current == nil {
			return
		}
		if err := current.Stop(); err != nil {
			showError(err)
		}
		setRunning(nil)
		updateButtons(false)
	}

	form := widget.NewForm(
		widget.NewFormItem("Interface", container.NewBorder(nil, nil, nil, rescanIfacesButton, ifaceSelect)),
		widget.NewFormItem("Profile", container.NewBorder(nil, nil, nil, container.NewHBox(addProfileButton, rescanButton), profileSelect)),
		widget.NewFormItem("Artifact roots", container.NewBorder(nil, nil, nil, container.NewVBox(addArtifactButton, removeArtifactButton), artifactList)),
		widget.NewFormItem("Bind", bindEntry),
		widget.NewFormItem("Flashing services", enableFlashServices),
		widget.NewFormItem("DHCP port", dhcpPortEntry),
		widget.NewFormItem("TFTP port", tftpPortEntry),
		widget.NewFormItem("Run root", runRootEntry),
	)

	controls := container.NewHBox(layout.NewSpacer(), startButton, stopButton)
	logHeader := container.NewHBox(widget.NewLabel("Logs"), layout.NewSpacer(), autoRefresh, refreshRunButton)
	logFilterRow := container.NewBorder(nil, nil, widget.NewLabel("Filter"), nil, logFilter)
	runSection := container.NewVBox(
		status,
		runDirLabel,
		container.NewHBox(networkStatus, layout.NewSpacer(), dhcpStatus, tftpStatus),
		widget.NewLabel("Clients"),
		clientsTable,
		widget.NewSeparator(),
		logHeader,
		logFilterRow,
		logView,
		widget.NewLabel("Events"),
		eventsList,
	)
	content := container.NewVBox(form, controls, widget.NewSeparator(), runSection)

	w.SetContent(content)
	w.Resize(fyne.NewSize(860, 680))
	w.SetOnClosed(func() {
		close(stopRefresh)
	})
	w.ShowAndRun()
}

func listProfiles(dir string) ([]profileOption, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("no profiles found")
	}
	sort.Strings(files)
	labels := make(map[string]int)
	for _, file := range files {
		labels[filepath.Base(file)]++
	}
	options := make([]profileOption, 0, len(files))
	for _, file := range files {
		base := filepath.Base(file)
		label := base
		if labels[base] > 1 {
			if rel, err := filepath.Rel(dir, file); err == nil {
				label = rel
			} else {
				label = file
			}
		}
		options = append(options, profileOption{Label: label, Path: file})
	}
	return options, nil
}

func ensureProfileOption(selectWidget *widget.Select, profileMap map[string]string, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	label := filepath.Base(path)
	if existing, ok := profileMap[label]; ok && existing != path {
		label = fmt.Sprintf("%s (%s)", label, filepath.Dir(path))
	}
	if existing, ok := profileMap[label]; ok && existing == path {
		return label
	}
	selectWidget.Options = append(selectWidget.Options, label)
	sort.Strings(selectWidget.Options)
	profileMap[label] = path
	selectWidget.Refresh()
	return label
}

func startRun(profilePath string, roots []string, bindAddr string, runRoot string, dhcpPort string, tftpPort string, ifaceName string, ifaceIP string, enableFlash bool) (*runHandle, error) {
	profile, err := profiles.LoadProfile(profilePath)
	if err != nil {
		return nil, err
	}
	if err := profiles.Validate(profile); err != nil {
		return nil, err
	}
	manifest, err := profiles.ResolveArtifacts(profile, roots)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(bindAddr) == "" {
		return nil, fmt.Errorf("bind address required")
	}
	targetIP := ifaceIP
	if enableFlash {
		targetIP = strings.TrimSpace(profile.Network.ServerIP)
		if targetIP == "" {
			return nil, fmt.Errorf("profile server_ip required for flashing")
		}
		bindAddr = net.JoinHostPort(targetIP, resolvePort(bindAddr))
	} else if ifaceIP != "" {
		if host := extractHost(bindAddr); host != "" && host != ifaceIP {
			return nil, fmt.Errorf("bind address must match selected interface (%s)", ifaceIP)
		}
	}
	if enableFlash {
		dhcpPort, err = normalizePort(dhcpPort)
		if err != nil {
			return nil, fmt.Errorf("dhcp port: %w", err)
		}
		tftpPort, err = normalizePort(tftpPort)
		if err != nil {
			return nil, fmt.Errorf("tftp port: %w", err)
		}
	}
	if strings.TrimSpace(runRoot) == "" {
		runRoot = "runs"
	}
	runID := time.Now().UTC().Format("20060102-150405")
	runDir := filepath.Join(runRoot, runID)
	logDir := filepath.Join(runDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("create run dir: %w", err)
	}
	manifestPath := filepath.Join(runDir, "manifest.json")
	if err := profiles.WriteManifest(manifestPath, manifest); err != nil {
		return nil, err
	}
	logPath := filepath.Join(logDir, "http.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	logger := logging.New(io.MultiWriter(logFile))
	store, err := sessions.NewStore(runID, runDir)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	var dhcpServer *dhcpd.Server
	var tftpServer *tftpd.Server
	var netSnapshot *netcfg.Snapshot
	if enableFlash {
		netSnapshot, err = netcfg.ApplyStaticIPv4(ifaceName, targetIP, profile.Network.CIDR)
		if err != nil {
			_ = store.Close()
			_ = logFile.Close()
			return nil, err
		}
		ifaceIP = targetIP
		dhcpServer, err = newDHCPServer(profile, ifaceName, targetIP, dhcpPort, logger, store)
		if err != nil {
			_ = netcfg.Restore(netSnapshot)
			_ = store.Close()
			_ = logFile.Close()
			return nil, err
		}
		if dhcpServer != nil {
			go func() {
				_ = dhcpServer.Serve()
			}()
		}
		if manifestHasKind(manifest, "tftp") {
			tftpBind := net.JoinHostPort(targetIP, tftpPort)
			tftpServer, err = tftpd.NewServer(tftpd.Config{
				BindAddr: tftpBind,
				Manifest: manifest,
				Logger:   logger,
				Sessions: store,
			})
			if err != nil {
				if dhcpServer != nil {
					_ = dhcpServer.Shutdown()
				}
				_ = netcfg.Restore(netSnapshot)
				_ = store.Close()
				_ = logFile.Close()
				return nil, err
			}
			go func() {
				_ = tftpServer.ListenAndServe()
			}()
		}
	}
	server, err := httpd.NewServer(httpd.Config{
		BindAddr: bindAddr,
		Manifest: manifest,
		Sessions: store,
		Logger:   logger,
	})
	if err != nil {
		if tftpServer != nil {
			tftpServer.Shutdown()
		}
		if dhcpServer != nil {
			_ = dhcpServer.Shutdown()
		}
		_ = store.Close()
		_ = logFile.Close()
		return nil, err
	}
	return &runHandle{
		server:    server,
		dhcp:      dhcpServer,
		tftp:      tftpServer,
		network:   netSnapshot,
		flashOn:   enableFlash,
		store:     store,
		logFile:   logFile,
		logPath:   logPath,
		eventPath: filepath.Join(runDir, "sessions.jsonl"),
		runID:     runID,
		runDir:    runDir,
		ifaceName: ifaceName,
		ifaceIP:   ifaceIP,
	}, nil
}

func loadLog(path string, filter string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return string(data), nil
	}
	filter = strings.ToLower(filter)
	lines := strings.Split(string(data), "\n")
	var builder strings.Builder
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), filter) {
			builder.WriteString(line)
			builder.WriteByte('\n')
		}
	}
	return builder.String(), nil
}

func loadEvents(path string) ([]sessions.SessionEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var events []sessions.SessionEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event sessions.SessionEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return events, err
	}
	return events, nil
}

func formatEvent(event sessions.SessionEvent) string {
	timestamp := "-"
	if !event.Time.IsZero() {
		timestamp = event.Time.Format(time.RFC3339)
	}
	parts := []string{timestamp, event.Type}
	if event.MAC != "" {
		parts = append(parts, "mac="+event.MAC)
	}
	if event.IP != "" {
		parts = append(parts, "ip="+event.IP)
	}
	if event.Details != nil {
		if path := event.Details["path"]; path != "" {
			parts = append(parts, "path="+path)
		}
		if status := event.Details["status"]; status != "" {
			parts = append(parts, "status="+status)
		}
	}
	return strings.Join(parts, " ")
}

type clientRow struct {
	MAC       string
	IP        string
	LastEvent string
	lastTime  time.Time
}

func buildClients(events []sessions.SessionEvent) []clientRow {
	clients := map[string]clientRow{}
	for _, event := range events {
		mac := strings.TrimSpace(event.MAC)
		if mac == "" {
			continue
		}
		row := clients[mac]
		if row.MAC == "" {
			row.MAC = mac
		}
		if event.IP != "" {
			row.IP = event.IP
		}
		if row.lastTime.IsZero() || event.Time.After(row.lastTime) {
			row.lastTime = event.Time
			row.LastEvent = formatEvent(event)
		}
		clients[mac] = row
	}
	list := make([]clientRow, 0, len(clients))
	for _, row := range clients {
		list = append(list, row)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].MAC < list[j].MAC
	})
	return list
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
		return nil, fmt.Errorf("profile server_ip (%s) must match selected interface (%s)", serverIP, ifaceIP)
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

func listInterfaces() ([]ifaceOption, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	options := make([]ifaceOption, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		ip := pickIPv4(addrs)
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		label := fmt.Sprintf("%s (%s", iface.Name, state)
		if ip == "" {
			label += ", no IPv4)"
		} else {
			label += ", " + ip + ")"
		}
		options = append(options, ifaceOption{
			Label: label,
			Name:  iface.Name,
			IP:    ip,
		})
	}
	sort.Slice(options, func(i, j int) bool {
		return options[i].Name < options[j].Name
	})
	return options, nil
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

func resolvePort(bindAddr string) string {
	_, port, err := net.SplitHostPort(bindAddr)
	if err == nil && port != "" {
		return port
	}
	return "8080"
}

func extractHost(bindAddr string) string {
	host, _, err := net.SplitHostPort(bindAddr)
	if err == nil {
		return host
	}
	if strings.Contains(bindAddr, ":") {
		return ""
	}
	return strings.TrimSpace(bindAddr)
}
