# Profile Schema

This document summarizes the current YAML schema implemented by `pkg/profiles`.
The canonical schema lives in the PRD and in the Go structs.

## Top-level
- `id` (string, required)
- `name` (string, required)
- `description` (string, optional)
- `network` (object, required)
- `dhcp` (object, optional)
- `boot` (object, required)
- `artifacts` (object, required)
- `imaging` (object, optional)
- `postboot` (object, optional)

## Notes
- All artifact paths are relative to an artifact root chosen at run start.
- Path traversal ("..") and absolute paths are rejected.
- At run start, a manifest is written to `runs/<run-id>/manifest.json`.
- `boot.http_root` is treated as a URL prefix for serving HTTP files.
