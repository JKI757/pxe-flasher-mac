# macOS Netboot Flasher (Go + Fyne) — PRD + Implementation Task List
Version: 0.1  
Date: 2025-12-23  
Primary OS: macOS  
UI: Fyne (BSD-3-Clause)  
Language: Go  

## 1) Summary
Build a macOS desktop app that turns a Mac into an “edge-device flashing station” for devices that boot over the network.

The app:
- Lets the user pick a **Device Profile** and supply **boot + install artifacts**.
- Automatically configures the selected Ethernet interface for an isolated flashing network.
- Serves the correct boot path for **UEFI PXE** and optionally **legacy BIOS PXE**.
- Supports two imaging flows:
  1) **Network-install**: device boots an installer/initramfs and then pulls the final image or packages over HTTP.
  2) **Full image push**: device boots a minimal environment and the Mac streams/pushes a disk image (over HTTP, SSH, or a custom protocol), then verifies success.
- Provides live logs, per-device session timelines, and an exportable support bundle.
- Restores the Mac’s networking state on stop/exit.

## 2) Goals / Non-goals
### Goals
- UEFI-first, BIOS optional.
- Profile-driven behavior (no code changes to add a new device type).
- Clean start/stop with strong rollback guarantees.
- Strict permissive OSS dependency policy (MIT/BSD/ISC/Apache-2.0).
- Safe by default: operate only on a user-selected interface; avoid touching primary uplink unless forced.

### Non-goals
- A general-purpose LAN DHCP server.
- Bundling third-party netboot loaders that would drag the project into copyleft licensing.
- Supporting every vendor netboot quirk out of the box. Instead: provide extensible profile hooks and artifact overrides.

## 3) Users
- Field techs flashing one device at a time via direct cable or a small switch.
- Lab engineers flashing many devices (sequentially or concurrently) with per-MAC rules.

## 4) Key Requirements
### Functional
- Select Ethernet interface (e.g., USB-C dongle) and bind services to it only.
- Start/stop:
  - Start configures IP, routes, optional NAT, then starts DHCP+TFTP+HTTP.
  - Stop shuts down services and restores previous network state and PF rules.
- Device Profiles:
  - Match clients by MAC, DHCP options (vendor class, user class), arch.
  - Choose boot filename and server endpoints per arch and boot mode.
  - Map artifacts to TFTP root and HTTP root.
- Boot modes:
  - **UEFI PXE via TFTP** (serve `bootx64.efi` etc).
  - **BIOS PXE via TFTP** (serve `pxelinux.0` / similar, user-supplied).
  - **UEFI HTTPBoot** (serve a user-supplied EFI loader over HTTP).
  - Optional **iPXE chain** support *only if user supplies binaries*.
- Imaging modes:
  - **Network-install**: provide kernel/initrd + installer config, then serve image/packages via HTTP.
  - **Full-image push**: boot minimal OS, then push `*.img`/`*.raw` via:
    - HTTP pull + verifier (device pulls from Mac), or
    - SSH push (Mac pushes), or
    - Custom “image receiver” protocol (future).
- Observability:
  - Live log view (filterable).
  - Per-device session timeline (DHCP lease → TFTP → HTTP → image push → verify).
  - Export bundle: profile + resolved artifact manifests + logs + session JSON.

### Non-functional
- Must run reliably on Apple Silicon and Intel Macs.
- Must handle multiple clients concurrently (at least 10) without UI lag.
- Avoid racey networking state changes; rollback must be deterministic.
- Security:
  - Privileged operations isolated to a helper.
  - Minimal IPC surface area; validate inputs; refuse path traversal in file serving.

## 5) Licensing Policy (hard constraint)
### Allowed
- MIT, BSD-2/3, ISC, Apache-2.0.
- Public-domain / CC0 (code) where applicable.

### Disallowed
- GPL/LGPL/AGPL and “copyleft” unless explicitly approved later.

### Netboot loader handling
Do **not** bundle or redistribute third-party bootloaders/EFI binaries that are copyleft.
Design for **user-supplied artifacts**:
- User points the app at a folder containing `bootx64.efi`, `grubx64.efi`, `pxelinux.0`, etc.
- The app serves those bytes. It does not ship them.

## 6) Proposed Tech Stack
- UI: Fyne (BSD-3-Clause): https://fyne.io/  
  License evidence (BSD-3-Clause): https://github.com/fyne-io/tools/blob/main/LICENSE
- DHCP: insomniacslk/dhcp (BSD-3-Clause): https://github.com/insomniacslk/dhcp  
  License: https://github.com/insomniacslk/dhcp/blob/master/LICENSE
- TFTP: pin/tftp (MIT): https://github.com/pin/tftp  
  License: https://github.com/pin/tftp/blob/master/LICENSE
- HTTP: Go stdlib `net/http`
- Optional packet decode for diagnostics (BSD-3-Clause): https://github.com/google/gopacket

Privileged helper pattern:
- Apple ServiceManagement `SMJobBless` docs: https://developer.apple.com/documentation/servicemanagement/smjobbless%28_%3A_%3A_%3A_%3A%29  
- Apple sample: https://github.com/fruitsamples/SMJobBless

PF / NAT docs:
- pf.conf manual (OpenBSD, conceptual reference): https://man.openbsd.org/pf.conf  
- macOS PF manual PDF (practical examples): https://murusfirewall.com/Documentation/OS%20X%20PF%20Manual.pdf  
- pfctl overview (macOS): https://ss64.com/mac/pfctl.html

## 7) System Architecture
### 7.1 Components
1) **GUI app (unprivileged)**  
   - Fyne UI
   - Profile + artifact management
   - Log viewer + session viewer
   - Talks to helper via IPC (XPC recommended)  
   - Never modifies network config directly

2) **Privileged helper (root)**  
   Responsibilities:
   - Configure selected interface (IP/route)
   - Add/remove PF anchor rules (NAT optional)
   - Run DHCP server (UDP/67), TFTP server (UDP/69), HTTP server (TCP)
   - Maintain a sessions database in the workspace directory
   - Expose narrow IPC API

3) **Workspace**  
   - `profiles/`
   - `artifacts/`
   - `runs/<run-id>/logs/`
   - `runs/<run-id>/sessions.jsonl`
   - `runs/<run-id>/manifest.json` (hashes, file sizes, resolved paths)

### 7.2 IPC (minimal surface)
- `ListIfaces() -> []Iface`
- `StartRun(req StartRequest) -> StartResponse`
- `StopRun(runID) -> StopResponse`
- `GetStatus() -> Status`
- `StreamLogs(runID) -> stream<LogLine>`
- `StreamSessions(runID) -> stream<SessionEvent>`
- `ExportBundle(runID, destPath) -> ExportResult`

**StartRequest**
- `ifaceName` (e.g., `en7`)
- `serverCIDR` (default `192.168.77.1/24`)
- `dhcpPool` (default `192.168.77.50-200`)
- `profilePath`
- `artifactRoots` (paths)
- `natMode` (off|on)
- `httpListen` (ip:port; default bind to server IP)
- `tftpRoot`, `httpRoot` (resolved)
- `safetyBypass` (bool, default false)

## 8) Device Profiles
Store profiles as YAML. GUI provides “create/edit” basics but must support advanced fields.

### 8.1 Schema (YAML)
```yaml
id: "deviceA"
name: "Device A (UEFI PXE)"
description: "UEFI x64 netboot with TFTP -> EFI loader -> kernel/initrd"
network:
  server_ip: "192.168.77.1"
  cidr: "192.168.77.1/24"
  pool_start: "192.168.77.50"
  pool_end: "192.168.77.200"
  lease_seconds: 600
dhcp:
  match:
    vendor_class_prefixes: ["PXEClient", "iPXE"]
    user_class_prefixes: ["iPXE"]
    mac_allowlist: []    # optional
    mac_denylist: []     # optional
  arch_map:
    # DHCP option 93 (client system arch) mapping
    # (values are examples; keep configurable)
    "UEFI_X86_64": { boot_filename: "bootx64.efi" }
    "BIOS_X86":    { boot_filename: "pxelinux.0" }
boot:
  mode: "tftp"     # tftp|httpboot
  tftp_root: "tftp/"
  http_root: "http/"
  # Optional per-MAC override (one-off fixes)
  per_mac:
    "AA:BB:CC:DD:EE:FF":
      boot_filename: "bootx64.efi"
      http_tags: ["special"]
artifacts:
  # Relative to selected artifact roots; resolved to absolute at run start
  tftp_files:
    - "boot/bootx64.efi"
    - "boot/grub.cfg"
  http_files:
    - "installer/vmlinuz"
    - "installer/initrd.img"
    - "images/deviceA.img.zst"
imaging:
  mode: "network_install"   # network_install|full_image_push|both
  network_install:
    kernel: "installer/vmlinuz"
    initrd: "installer/initrd.img"
    cmdline_template: "console=ttyS0 ip=dhcp inst.repo=http://{server_ip}/repo"
  full_image_push:
    method: "http_pull"     # http_pull|ssh_push
    image: "images/deviceA.img.zst"
    verify:
      sha256: "auto"        # auto|<hex>
postboot:
  # Optional future hook: wait for SSH then run commands
  wait_for_ssh: false
```

### 8.2 Profile resolution rules
At run start:
- Validate all referenced artifacts exist.
- Produce a **manifest** with:
  - absolute path, size, sha256
  - served URL/path for each artifact
- Helper refuses to start if manifest generation fails.

## 9) Networking Behavior
### 9.1 Interface configuration
- Configure selected interface with static IP `server_ip`.
- Add route(s) if needed.
- Never touch other interfaces unless NAT mode is enabled.

### 9.2 NAT mode (optional)
- Use PF with a dedicated anchor, e.g. `com.example.netbootflasher/*`
- On start:
  - load anchor file
  - enable pf (if not already)
- On stop:
  - remove anchor rules and restore previous pf enabled/disabled state (if we changed it)

### 9.3 Safety checks
- Default block: refuse to run if selected interface appears to be primary route to internet.
- Require explicit “safety bypass” toggle to proceed in that case.

## 10) Imaging Flows
### 10.1 Network-install (device pulls)
- Device netboots into installer environment.
- Installer fetches packages/image from Mac over HTTP.
- Success signal options:
  - installer calls back to `http://{server_ip}/done?mac=...&status=ok`
  - or the helper watches for a known HTTP request pattern
  - or the user confirms (fallback)

### 10.2 Full-image push
Support both initially, but make `http_pull` the first implementation:
- `http_pull`: device boots minimal OS, runs a small script that downloads an image from the Mac and writes it to disk.
- `ssh_push`: Mac pushes image via SSH (requires device to bring up SSH keys/credentials; often messy).

Verification:
- Provide sha256 for the image (auto-calc at run start).
- Device reports sha256 back to helper, or helper requests it if SSH is available.

## 11) UX Requirements (Fyne)
### Screens
1) **Run Setup**
   - Interface picker (list + link state)
   - Profile picker
   - Artifact roots picker (folders)
   - Toggle: NAT mode
   - Start button
2) **Live Run**
   - Status header (RUNNING / STOPPING / ERROR)
   - Connected clients table (MAC, IP, stage, last activity)
   - Log panel (filter/search)
   - “Export bundle” button
   - Stop button
3) **Profiles**
   - List profiles
   - Import/export profile YAML
   - Minimal editor for common fields (advanced users edit YAML externally)

## 12) Repository Layout (Codex target)
```
netboot-flasher/
  LICENSE
  README.md
  docs/
    prd.md
    profile-schema.md
    security.md
  cmd/
    flasher-gui/
      main.go
    flasher-helper/
      main.go
  pkg/
    profiles/
      load.go
      validate.go
      manifest.go
    netcfg/
      snapshot.go
      apply.go
      restore.go
    dhcpd/
      server.go
      match.go
      arch.go
    tftpd/
      server.go
      filesystem.go
    httpd/
      server.go
      routes.go
    sessions/
      model.go
      store.go
      events.go
    ipc/
      protocol.go
      client.go
      server.go
    logging/
      logger.go
  internal/
    mac/
      smjobbless/
      pf/
      scnet/
  scripts/
    check-licenses.sh
    dev-run.sh
  test/
    profiles/
    integration/
```

## 13) Implementation Tasks (detailed)
### 13.1 Project scaffolding
- [x] Initialize Go module, set minimum Go version.
- [x] Add `LICENSE` (MIT or BSD-3 for your project; choose one).
- [ ] Add CI:
  - [x] `go test ./...`
  - [ ] `golangci-lint`
  - [ ] dependency license gate (see 13.2)
  - [x] macOS package (app + dmg)
  - [x] codesign + notarize when secrets are configured

### 13.2 Dependency + license gate (must-have)
- [x] Implement `scripts/check-licenses.sh`:
  - Use `go list -m -json all` + parse licenses from module metadata when available (fallback to scanning LICENSE files).
  - Fail build if any dependency is GPL/LGPL/AGPL or unknown.
- [x] Document “User-supplied artifacts only” policy for bootloaders.

### 13.3 Profiles + manifest
- [x] Define Go structs for profile schema.
- [x] YAML load + validation:
  - [x] required fields
  - [x] artifact path resolution (relative → absolute)
  - [x] prevent `..` traversal
- [x] Manifest generation:
  - [x] sha256 for each artifact
  - [x] stable IDs for files
  - [x] output `manifest.json` into run workspace

### 13.4 DHCP server
- [x] Implement DHCPv4 server bound to selected interface IP.
- [ ] Lease tracking:
  - [x] in-memory leases
  - [ ] persist leases per run (optional)
- [x] Option handling:
  - [x] option 66/67 (TFTP next-server + bootfile)
  - [x] option 93 arch mapping
  - [x] vendor/user-class matching
- [x] Per-MAC overrides from profile.

### 13.5 TFTP server
- [x] Serve from resolved `tftp_root`.
- [x] Enforce read-only; refuse writes.
- [x] Path sanitization and logging.
- [x] Metrics: bytes transferred, errors.

### 13.6 HTTP server
- [x] Serve from resolved `http_root`.
- [x] Add endpoints:
  - [x] `/health`
  - [x] `/done` (optional callback)
  - [x] `/manifest` (serve manifest to device/tools)
- [x] Add Range request support (stdlib does this with `http.ServeContent` if you wire it right).

### 13.7 Sessions + event model
- [x] Session keyed by MAC + runID.
- [x] Emit events:
  - [x] DHCP_DISCOVER/ACK
  - [x] TFTP_READ(file)
  - [x] HTTP_GET(path)
  - [x] IMAGE_DONE(status, details)
- [x] Persist sessions to `sessions.jsonl` for streaming and export.

### 13.8 macOS privileged helper
- [x] Create helper binary `flasher-helper`.
- [ ] Implement install/register using SMJobBless approach.
- [ ] Ensure helper only accepts IPC from the signed GUI app.
- [ ] Separate “core servers” from “system modification” logic so the helper can run in a minimal privileged mode.

### 13.9 macOS network config + rollback
- [ ] Snapshot state for selected interface:
  - [x] IP config
  - [ ] routes (as relevant)
  - [ ] PF enabled state (if using NAT)
- [ ] Apply isolated config:
  - [x] set static IP `server_ip`
  - [x] ensure interface is up
- [ ] Restore on stop:
  - [x] revert interface config
  - [ ] remove PF anchors
  - [ ] disable PF if we enabled it

### 13.10 PF NAT mode (deferred)
- [ ] Implement anchor file writer (per run).
- [ ] Commands (via `pfctl`) executed by helper.
- [ ] Test that:
  - [ ] NAT works when enabled
  - [ ] anchor removed and state restored on stop

### 13.11 GUI (Fyne)
- [ ] Setup screen:
  - [x] interface list
  - [x] profile list/import
  - [x] artifact root selectors
  - [ ] NAT toggle
- [ ] Run screen:
  - [x] log panel with search/filter
  - [x] clients table
  - [ ] export bundle
  - [x] stop
- [ ] Profile screen:
  - [ ] list/import/export
  - [ ] open profile folder
- [ ] “Crash safety”:
  - [ ] on GUI crash/restart, detect a running helper/run and offer to stop/restore.

### 13.12 Export bundle
- [ ] Zip:
  - profile YAML
  - manifest.json
  - logs
  - sessions.jsonl
  - system info (macOS version, iface name, IP config summary)
- [ ] Redact: avoid leaking unrelated interface details unless user opts in.

### 13.13 Tests
- [ ] Unit:
  - profile validation
  - DHCP match logic
  - path sanitization
- [ ] Integration (local):
  - start servers on loopback / ephemeral ports
  - simulate DHCP packets (library-level)
  - TFTP fetch of a known file
  - HTTP fetch + range request
- [ ] Manual test checklist (doc):
  - UEFI PXE boot
  - BIOS PXE boot (optional)
  - UEFI HTTPBoot (optional)
  - start/stop rollback (repeat 20x)

## 14) “Codex Implementation Notes” (hand-off)
- Implement in small vertical slices:
  1) Profiles + manifest + HTTP server (unprivileged CLI)
  2) Add TFTP
  3) Add DHCP
  4) Add sessions/events + CLI UI logs
  5) Add helper and macOS network control
  6) Add Fyne GUI
- Keep helper logic in `internal/mac/*` and make it the only layer allowed to call `pfctl` or interface config tools.
- Treat all artifact paths as untrusted; enforce root directories and sanitize.
- Always bind servers to the chosen interface’s IP, never `0.0.0.0` by default.
- On stop, restore first, then exit. If restore fails, keep trying and surface a hard error with remediation steps.

## 15) Open Questions (safe defaults)
- DHCPv6: default “later”; many PXE stacks still use DHCPv4.
- Concurrency: support multiple clients, but imaging “push” may be serialized per profile.
- Secure boot: assume the user provides signed EFI loaders if required.

---
## Appendix A — Source references (non-Wikipedia)
- Fyne license (BSD-3-Clause): https://github.com/fyne-io/tools/blob/main/LICENSE
- insomniacslk/dhcp (BSD-3-Clause): https://github.com/insomniacslk/dhcp / https://github.com/insomniacslk/dhcp/blob/master/LICENSE
- pin/tftp (MIT): https://github.com/pin/tftp / https://github.com/pin/tftp/blob/master/LICENSE
- Apple SMJobBless docs: https://developer.apple.com/documentation/servicemanagement/smjobbless%28_%3A_%3A_%3A_%3A%29
- Apple SMJobBless sample: https://github.com/fruitsamples/SMJobBless
- PF config reference: https://man.openbsd.org/pf.conf
- macOS PF manual PDF: https://murusfirewall.com/Documentation/OS%20X%20PF%20Manual.pdf
- pfctl overview: https://ss64.com/mac/pfctl.html
