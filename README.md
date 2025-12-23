# Netboot Flasher (macOS)

This repository implements a macOS desktop tool that turns a Mac into a
profile-driven netboot flashing station. Includes profile loading, artifact
validation, manifest generation, and HTTP/DHCP/TFTP servers for serving netboot
artifacts.

## Requirements
- Go 1.24+

## Quick start (HTTP-only slice)
1. Create a workspace with a profile and artifacts (a sample lives in `profiles/` and `artifacts/`).
2. Start the helper in HTTP mode (you can omit `--profile` to select interactively from `profiles/` or paste a YAML path if the folder is missing, and omit `--artifact-root` to select at runtime, defaulting to `artifacts/` if present):

```bash
./scripts/dev-run.sh \
  --profile /path/to/profile.yaml \
  --artifact-root /path/to/artifacts \
  --http-root http \
  --bind 192.168.77.1:8080
```

Optional DHCP/TFTP (configures the selected interface to the profile server IP and restores it on exit; requires explicit enable flags):

```bash
./scripts/dev-run.sh \
  --profile /path/to/profile.yaml \
  --artifact-root /path/to/artifacts \
  --bind 192.168.77.1:8080 \
  --iface en7 \
  --dhcp-port 6767 \
  --tftp-port 6969 \
  --enable-dhcp \
  --enable-tftp
```

Note: macOS may require external linking for `go run` to include `LC_UUID`. The
script already sets this; if you run manually, add
`-ldflags='-linkmode=external'`.

## GUI (debug slice)
Run the minimal GUI to pick a profile and artifact roots without CLI prompts:

```bash
./scripts/dev-run-gui.sh
```

The GUI uses Fyne (BSD-3-Clause). The script forces `-mod=mod` so Go can fetch
modules even if a partial `vendor/` directory exists.

DHCP/TFTP ports default to 6767/6969 for unprivileged runs. For real PXE use,
set them to 67/69 (requires root or the privileged helper) and enable them via
the GUI checkbox or CLI flags.

This will:
- Validate the profile and artifacts.
- Generate `runs/<run-id>/manifest.json`.
- Serve `/health`, `/manifest`, and HTTP files under the configured root.

## Packaging (macOS)
Local build script:

```bash
./scripts/build-macos.sh
```

This writes `dist/Netboot Flasher.app`, `dist/Netboot-Flasher.dmg`, and `dist/flasher-helper`.
The script will auto-install (or reinstall) the Fyne CLI if needed.

Local packaging uses the Fyne CLI:

```bash
fyne package -os darwin -src ./cmd/flasher-gui -name "Netboot Flasher" -appID "com.netbootflasher.app" -icon assets/icon.png
hdiutil create -volname "Netboot Flasher" -srcfolder "Netboot Flasher.app" -ov -format UDZO "Netboot-Flasher.dmg"
```

GitHub Actions workflow `.github/workflows/macos-package.yml` builds:
- `dist/Netboot Flasher.app`
- `dist/Netboot-Flasher.dmg`
- `dist/flasher-helper`

To enable codesigning + notarization in CI, set secrets:
- `APPLE_CERT_P12` (base64-encoded Developer ID cert)
- `APPLE_CERT_P12_PASSWORD`
- `APPLE_CERT_ID` (e.g. `Developer ID Application: ...`)
- `APPLE_ID`, `APPLE_APP_PASSWORD`, `APPLE_TEAM_ID`
- optional `APPLE_KEYCHAIN_PASSWORD`

## Layout
See `docs/prd.md` for the full plan and requirements.
