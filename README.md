# ClamAV Security Dashboard for ZimaOS

A browser dashboard for ClamAV on ZimaOS with automatic storage discovery, live scan progress, persistent history and confirmed quarantine actions.

## Features

- Discovers each user's ZimaOS disks beneath `/media`
- Requires explicit approval before a folder can be scanned
- Excludes AppData, Docker, databases, virtual machines, backups, snapshots, Borg repositories, restore folders, trash and system metadata
- Shows exact folders included in every scan
- Measures file count and total folder size before scanning
- Shows current file, scanned bytes, remaining bytes, speed, elapsed time and ETA
- Stores scan history, detections, skipped files and errors
- Quarantines only after a confirmed user action
- Validates the recorded path and SHA-256 digest before restoring
- Requires `DELETE PERMANENTLY` before deleting a quarantined file

Scanning is read-only. Files are never removed automatically.

## ZimaOS Custom App installation

1. Download `docker-compose.yml` from this repository.
2. Open **App Store > Install Custom App > Import**.
3. Import the YAML file.
4. Confirm port `8099` is available, then install.
5. Open `http://ZIMAOS-IP:8099`.
6. Select approved folders and save before starting a scan.

Persistent data is stored under:

```text
/DATA/AppData/clamav-dashboard
```

## Security model

The dashboard receives `/media` at `/host-media` with write access because quarantine and restore must move a confirmed infected file. Application controls restrict these actions to folders explicitly approved by the user. Quarantined files are kept beneath `/DATA/AppData/clamav-dashboard/data/quarantine`.

The ClamAV daemon is not published to the host network. Only the dashboard port is exposed.

## Architecture

- `clamav/clamav:1.5_base` provides the official ClamAV daemon and signature updates.
- `ghcr.io/jacko88888/clamav-dashboard:0.2.1` provides the dashboard.
- A private Compose network connects the two services.

## Current limitation

Progress advances after each file completes. A single large archive can remain at the same percentage while ClamAV inspects it. Cancellation waits for the current file to finish.

## License

MIT
