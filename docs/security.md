# Security Notes

- All privileged operations will move to a macOS helper using SMJobBless.
- The unprivileged app never edits network configuration directly.
- HTTP/TFTP servers are bound only to the selected interface address.
- Artifact paths are validated to prevent traversal and accidental escape from
  the user-selected artifact roots.
- No third-party bootloaders are bundled; users supply their own binaries.
