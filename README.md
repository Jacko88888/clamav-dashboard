# ClamAV Security Dashboard for ZimaOS

**Created exclusively for ZimaOS.** This browser-based antivirus dashboard follows the ZimaOS storage layout and Custom App workflow. It combines the official ClamAV engine with automatic disk discovery, controlled folder approval, live scan progress, persistent evidence and confirmed quarantine actions.

Tested on ZimaCube Pro and ZimaBoard.

## Features

- Automatically discovers each user's ZimaOS disks and folders beneath `/media`
- Requires explicit approval before a folder can be scanned
- Shows a clearly green **Approved folders saved** confirmation state
- Excludes AppData, Docker data, databases, virtual machines, backups, snapshots, Borg repositories, restore folders, trash and system metadata
- Shows the exact folders included in every scan
- Measures file count and total folder size before scanning
- Shows the current file, scanned bytes, remaining bytes, speed, elapsed time and ETA
- Stores persistent scan history, detections, skipped files and errors
- Displays the detected signature and exact affected path
- Quarantines only after a separate confirmed user action
- Records the original path, size, signature and SHA-256 digest
- Validates the recorded path and SHA-256 digest before restoring
- Restores a quarantined file to its original location only after confirmation
- Requires `DELETE PERMANENTLY` before deleting a quarantined file
- Retains restored and deleted quarantine records as evidence

Scanning does not modify files. The application never quarantines or deletes a file automatically.

## ZimaOS Custom App installation

First, check whether the default dashboard port is available:

```bash
ss -lnt | grep ':8099 ' || echo "PORT 8099 AVAILABLE"
```

If port `8099` is occupied, select another free host port and change both `ports` and `x-casaos.port_map` in the YAML below.

Open **App Store > Install Custom App**, switch to **YAML**, and import:

```yaml
services:
  clamav-server:
    image: clamav/clamav:1.5_base
    restart: unless-stopped
    environment:
      TZ: ${TZ:-UTC}
      FRESHCLAM_CHECKS: "12"
      CLAMD_CONF_MaxThreads: "4"
      CLAMD_CONF_MaxFileSize: 512M
      CLAMD_CONF_MaxScanSize: 2G
      CLAMD_CONF_StreamMaxLength: 512M
    volumes:
      - /DATA/AppData/clamav-dashboard/clamav:/var/lib/clamav
    networks:
      - clamav-security

  clamav-dashboard:
    image: ghcr.io/jacko88888/clamav-dashboard:0.2.3
    restart: unless-stopped
    depends_on:
      clamav-server:
        condition: service_healthy
    ports:
      - "8099:8080"
    environment:
      TZ: ${TZ:-UTC}
      CLAMAV_HOST: clamav-server
      CLAMAV_PORT: "3310"
      DATA_DIR: /data
      MEDIA_ROOT: /host-media
      MAX_STREAM_BYTES: "536870912"
    volumes:
      - /DATA/AppData/clamav-dashboard/data:/data
      - /media:/host-media:rw
    networks:
      - clamav-security
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=256m
    security_opt:
      - no-new-privileges:true

networks:
  clamav-security:

x-casaos:
  title:
    custom: ClamAV Security Dashboard
    en_US: ClamAV Security Dashboard
  icon: https://raw.githubusercontent.com/Cisco-Talos/clamav/main/logo.png
  main: clamav-dashboard
  scheme: http
  port_map: "8099"
  index: /
```

Open:

```text
http://YOUR-ZIMAOS-IP:8099
```

Select the required folders and click **Save approved folders**. Wait for the button to turn green before starting a scan.

Persistent application data and quarantine evidence are stored under:

```text
/DATA/AppData/clamav-dashboard
```

## Security model

The dashboard mounts `/media` at `/host-media` with write access because confirmed quarantine and restore operations must move files from and back to their original locations.

- Ordinary scanning is non-destructive
- Only explicitly approved folders can be scanned
- Quarantine requires a separate confirmed action
- Restore validates the original path and recorded SHA-256 digest
- Permanent deletion requires explicit confirmation
- The ClamAV daemon is isolated on the private Compose network and is not published to the host
- Only the dashboard web port is exposed

## EICAR validation

Version 0.2.3 completed a controlled end-to-end test using the harmless industry-standard EICAR antivirus test file.

The validation confirmed:

- Detection as `Eicar-Test-Signature`
- Exact affected path and signature displayed
- Confirmed quarantine removed the original file from its storage folder
- Original path, file size and SHA-256 digest were recorded
- Restore returned the file to the exact original location with the same SHA-256 digest
- Re-quarantine and permanent deletion removed the file successfully
- Restored and deleted records remained available in the persistent quarantine history

## Architecture

- `clamav/clamav:1.5_base` provides the official ClamAV daemon and signature updates
- `ghcr.io/jacko88888/clamav-dashboard:0.2.3` provides the ZimaOS dashboard
- A private Compose network connects the two services
- ZimaOS storage is discovered from the mounted `/media` hierarchy

## Current limitation

Progress advances after each file completes. A large file or archive can remain at the same percentage while ClamAV inspects it. Cancellation waits for the current file to finish.

## Source and container

Repository:

```text
https://github.com/Jacko88888/clamav-dashboard
```

Container image:

```text
ghcr.io/jacko88888/clamav-dashboard:0.2.3
```

## License

MIT
