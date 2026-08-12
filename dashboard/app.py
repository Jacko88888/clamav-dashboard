import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import struct
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request


APP_VERSION = "0.2.1"
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav-server")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "clamav-dashboard.db"
CONFIG_PATH = DATA_DIR / "config.json"
MEDIA_ROOT = Path(os.getenv("MEDIA_ROOT", "/host-media"))
MAX_STREAM_BYTES = int(os.getenv("MAX_STREAM_BYTES", str(512 * 1024 * 1024)))
SOCKET_TIMEOUT = int(os.getenv("CLAMAV_SOCKET_TIMEOUT", "180"))
MAX_DETAIL_ITEMS = 250
ACTION_TOKEN = secrets.token_urlsafe(32)

EXCLUDED_NAMES = {
    "appdata", "docker", "database", "databases", "db", "vms", "vm",
    "backup", "backups", "snapshot", "snapshots", "borg", "borg-repos",
    "system volume information", "$recycle.bin", ".trash", ".zima_encrypted_folders",
    ".zimaos_storage.json",
    "zimabrain-full-snapshots", "zimabrain-full-restore-tests",
}
EXCLUDED_SUFFIXES = (".img", ".img.gz", ".qcow2", ".vdi", ".vmdk")
EXCLUDED_TERMS = (
    "backup", "snapshot", "borg", "restore", "database", "appdata", "docker",
)

app = Flask(__name__)
job_lock = threading.Lock()
active_job = None


@app.before_request
def verify_action_token():
    if request.method in {"POST", "PUT", "DELETE"} and request.path.startswith("/api/"):
        if not secrets.compare_digest(request.headers.get("X-Dashboard-Token", ""), ACTION_TOKEN):
            return jsonify({"error": "Invalid or missing dashboard action token"}), 403


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'"
    )
    return response


def load_config():
    if not CONFIG_PATH.is_file():
        return {"approved": []}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"approved": []}
    approved = data.get("approved")
    return {"approved": approved if isinstance(approved, list) else []}


def save_config(config):
    temporary = CONFIG_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(CONFIG_PATH)


def is_excluded_name(name):
    lowered = name.casefold()
    return (
        lowered in EXCLUDED_NAMES
        or lowered.endswith(EXCLUDED_SUFFIXES)
        or any(term in lowered for term in EXCLUDED_TERMS)
    )


def relative_media_path(path):
    return path.relative_to(MEDIA_ROOT).as_posix()


def safe_media_path(relative, require_exists=True):
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        return None
    candidate = MEDIA_ROOT.joinpath(*Path(relative).parts)
    try:
        root = MEDIA_ROOT.resolve(strict=True)
        resolved = candidate.resolve(strict=require_exists)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return candidate


def discover_disk_roots():
    roots = []
    seen = set()
    if not MEDIA_ROOT.is_dir():
        return roots
    marker_patterns = (
        "*/.zimaos_storage.json",
        "*/*/.zimaos_storage.json",
        "*/*/*/.zimaos_storage.json",
    )
    markers = []
    for pattern in marker_patterns:
        markers.extend(MEDIA_ROOT.glob(pattern))
    candidates = [marker.parent for marker in markers]
    if not candidates:
        candidates = [path for path in MEDIA_ROOT.iterdir() if path.is_dir()]
    for path in sorted(candidates, key=lambda item: str(item).casefold()):
        try:
            relative = relative_media_path(path)
            resolved = path.resolve(strict=True)
        except (OSError, ValueError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        roots.append({"id": hashlib.sha256(relative.encode()).hexdigest()[:12], "label": relative, "path": relative})
    return roots


def approved_paths():
    output = []
    for relative in load_config()["approved"]:
        path = safe_media_path(relative)
        if path and path.is_dir() and not any(is_excluded_name(part) for part in Path(relative).parts):
            output.append((relative, path))
    return output


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_connection():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def add_column(connection, table, definition):
    name = definition.split()[0]
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    with db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_key TEXT NOT NULL,
                root_label TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                files_total INTEGER NOT NULL DEFAULT 0,
                bytes_total INTEGER NOT NULL DEFAULT 0,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                bytes_scanned INTEGER NOT NULL DEFAULT 0,
                infected INTEGER NOT NULL DEFAULT 0,
                skipped INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                detections_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        add_column(connection, "scans", "skipped_json TEXT NOT NULL DEFAULT '[]'")
        add_column(connection, "scans", "error_json TEXT NOT NULL DEFAULT '[]'")
        add_column(connection, "scans", "scan_roots_json TEXT NOT NULL DEFAULT '[]'")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                signature TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                status TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                restored_at TEXT,
                deleted_at TEXT
            )
            """
        )


def clamd_command(command, terminator=b"\0"):
    with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=SOCKET_TIMEOUT) as client:
        client.settimeout(SOCKET_TIMEOUT)
        client.sendall(b"z" + command.encode("utf-8") + b"\0")
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if terminator in chunk:
                break
        return b"".join(chunks).rstrip(b"\0\n").decode("utf-8", errors="replace")


def scan_stream(path):
    with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=SOCKET_TIMEOUT) as client:
        client.settimeout(SOCKET_TIMEOUT)
        client.sendall(b"zINSTREAM\0")
        with path.open("rb") as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                client.sendall(struct.pack("!I", len(block)))
                client.sendall(block)
        client.sendall(struct.pack("!I", 0))
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\0" in chunk:
                break
        return b"".join(chunks).rstrip(b"\0\n").decode("utf-8", errors="replace")


def record_limited(items, value):
    if len(items) < MAX_DETAIL_ITEMS:
        items.append(value)


def allowed_scan_path(path):
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    for _, root in approved_paths():
        try:
            resolved.relative_to(root.resolve(strict=True))
            return True
        except (ValueError, OSError):
            continue
    return False


def allowed_restore_path(path):
    candidate = path.resolve(strict=False)
    try:
        relative = candidate.relative_to(MEDIA_ROOT.resolve(strict=True))
    except (ValueError, OSError):
        return False
    if any(is_excluded_name(part) for part in relative.parts):
        return False
    for _, root in approved_paths():
        try:
            candidate.relative_to(root.resolve(strict=True))
            return True
        except (ValueError, OSError):
            continue
    return False


def allowed_quarantine_path(path):
    try:
        path.resolve(strict=False).relative_to(QUARANTINE_DIR.resolve(strict=True))
        return True
    except (ValueError, OSError):
        return False


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class ScanJob:
    def __init__(self, scan_id, root_key, label, root_paths):
        self.scan_id = scan_id
        self.root_key = root_key
        self.label = label
        self.root_paths = root_paths
        self.folders = [relative_media_path(path) for path in root_paths]
        self.phase = "queued"
        self.status = "running"
        self.current_file = ""
        self.directories_indexed = 0
        self.files_total = 0
        self.bytes_total = 0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.infected = 0
        self.skipped = 0
        self.errors = 0
        self.detections = []
        self.skipped_details = []
        self.error_details = []
        self.started_monotonic = time.monotonic()
        self.scan_started_monotonic = None
        self.started_at = utc_now()
        self.cancel_event = threading.Event()

    def snapshot(self):
        elapsed_origin = self.scan_started_monotonic or self.started_monotonic
        elapsed = max(0, time.monotonic() - elapsed_origin)
        percent = 0
        if self.phase == "scanning" and self.bytes_total:
            percent = min(100, round(self.bytes_scanned * 100 / self.bytes_total, 1))
        elif self.phase == "finished" and self.status in ("clean", "infected"):
            percent = 100
        byte_rate = self.bytes_scanned / elapsed if elapsed and self.phase == "scanning" else 0
        file_rate = self.files_scanned / elapsed if elapsed and self.phase == "scanning" else 0
        remaining = max(0, self.bytes_total - self.bytes_scanned)
        eta = round(remaining / byte_rate) if byte_rate > 0 else None
        return {
            "id": self.scan_id,
            "root_key": self.root_key,
            "root_label": self.label,
            "folders": list(self.folders),
            "phase": self.phase,
            "status": self.status,
            "current_file": self.current_file,
            "directories_indexed": self.directories_indexed,
            "files_total": self.files_total,
            "bytes_total": self.bytes_total,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "bytes_remaining": remaining,
            "bytes_per_second": round(byte_rate),
            "files_per_second": round(file_rate, 2),
            "infected": self.infected,
            "skipped": self.skipped,
            "errors": self.errors,
            "elapsed_seconds": round(elapsed),
            "eta_seconds": eta,
            "percent": percent,
            "detections": list(self.detections),
            "skipped_details": list(self.skipped_details),
            "error_details": list(self.error_details),
        }


def enumerate_files(job):
    files = []
    for selected_root in job.root_paths:
        for current_root, directories, filenames in os.walk(selected_root, followlinks=False):
            directories[:] = [name for name in sorted(directories) if not is_excluded_name(name)]
            filenames.sort()
            job.directories_indexed += 1
            if job.cancel_event.is_set():
                break
            for filename in filenames:
                path = Path(current_root) / filename
                job.current_file = str(path)
                if is_excluded_name(filename):
                    job.skipped += 1
                    record_limited(job.skipped_details, {"file": str(path), "reason": "Excluded by safety policy"})
                    continue
                try:
                    if path.is_symlink() or not path.is_file():
                        job.skipped += 1
                        record_limited(job.skipped_details, {"file": str(path), "reason": "Not a regular file"})
                        continue
                    size = path.stat().st_size
                    files.append((path, size))
                    job.files_total += 1
                    job.bytes_total += size
                except OSError as exc:
                    job.errors += 1
                    record_limited(job.error_details, {"file": str(path), "error": str(exc)})
        if job.cancel_event.is_set():
            break
    return files


def save_job(job):
    snapshot = job.snapshot()
    with db_connection() as connection:
        connection.execute(
            """
            UPDATE scans SET finished_at = ?, status = ?, files_total = ?, bytes_total = ?,
                files_scanned = ?, bytes_scanned = ?, infected = ?, skipped = ?, errors = ?,
                detections_json = ?, skipped_json = ?, error_json = ?, scan_roots_json = ?
                WHERE id = ?
            """,
            (
                utc_now(), snapshot["status"], snapshot["files_total"], snapshot["bytes_total"],
                snapshot["files_scanned"], snapshot["bytes_scanned"], snapshot["infected"],
                snapshot["skipped"], snapshot["errors"], json.dumps(snapshot["detections"]),
                json.dumps(snapshot["skipped_details"]), json.dumps(snapshot["error_details"]),
                json.dumps(snapshot["folders"]),
                job.scan_id,
            ),
        )


def run_scan(job):
    global active_job
    try:
        job.phase = "indexing"
        files = enumerate_files(job)
        if job.cancel_event.is_set():
            job.status = "cancelled"
            return
        job.phase = "scanning"
        job.current_file = ""
        job.scan_started_monotonic = time.monotonic()
        for path, size in files:
            if job.cancel_event.is_set():
                job.status = "cancelled"
                break
            job.current_file = str(path)
            if size > MAX_STREAM_BYTES:
                job.skipped += 1
                job.files_scanned += 1
                job.bytes_scanned += size
                record_limited(job.skipped_details, {"file": str(path), "reason": "Exceeds stream limit", "size": size})
                continue
            try:
                result = scan_stream(path)
                if result.endswith(" FOUND"):
                    signature = result.split(":", 1)[-1].rsplit(" FOUND", 1)[0].strip()
                    job.infected += 1
                    job.detections.append({"scan_id": job.scan_id, "file": str(path), "signature": signature, "size": size})
                elif not result.endswith(" OK"):
                    job.errors += 1
                    record_limited(job.error_details, {"file": str(path), "error": result})
            except (OSError, socket.timeout) as exc:
                job.errors += 1
                record_limited(job.error_details, {"file": str(path), "error": str(exc)})
            finally:
                job.files_scanned += 1
                job.bytes_scanned += size
        if job.status == "running":
            job.status = "infected" if job.infected else "clean"
    except Exception as exc:
        app.logger.exception("Scan job failed")
        job.status = "failed"
        job.errors += 1
        record_limited(job.error_details, {"file": job.current_file, "error": str(exc)})
    finally:
        job.phase = "finished"
        job.current_file = ""
        save_job(job)
        with job_lock:
            if active_job is job:
                active_job = None


def row_to_scan(row):
    item = dict(row)
    item["detections"] = json.loads(item.pop("detections_json") or "[]")
    item["skipped_details"] = json.loads(item.pop("skipped_json", "[]") or "[]")
    item["error_details"] = json.loads(item.pop("error_json", "[]") or "[]")
    item["folders"] = json.loads(item.pop("scan_roots_json", "[]") or "[]")
    if not item["folders"] and item.get("root_key") not in (None, "__all__"):
        item["folders"] = [item["root_key"]]
    return item


def history_rows(limit=25):
    with db_connection() as connection:
        rows = connection.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [row_to_scan(row) for row in rows]


def scan_by_id(scan_id):
    with db_connection() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return row_to_scan(row) if row else None


def quarantine_rows():
    with db_connection() as connection:
        rows = connection.execute("SELECT * FROM quarantine ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


@app.get("/")
def dashboard():
    return render_template("index.html", version=APP_VERSION, action_token=ACTION_TOKEN)


@app.get("/api/storage")
def storage_discovery():
    approved = set(load_config()["approved"])
    disks = []
    for disk in discover_disk_roots():
        root = safe_media_path(disk["path"])
        folders = [{
            "name": "Entire disk (safe exclusions applied)",
            "path": disk["path"],
            "excluded": False,
            "approved": disk["path"] in approved,
            "whole_disk": True,
        }]
        if root:
            try:
                children = sorted(root.iterdir(), key=lambda item: item.name.casefold())
            except OSError:
                children = []
            for child in children:
                if not child.is_dir() or child.is_symlink():
                    continue
                relative = relative_media_path(child)
                excluded = is_excluded_name(child.name)
                folders.append({
                    "name": child.name,
                    "path": relative,
                    "excluded": excluded,
                    "approved": relative in approved,
                    "whole_disk": False,
                })
        disks.append({**disk, "folders": folders})
    return jsonify({"media_root": str(MEDIA_ROOT), "disks": disks, "approved": sorted(approved)})


@app.put("/api/storage/approved")
def update_approved_storage():
    payload = request.get_json(silent=True) or {}
    requested = payload.get("approved")
    if not isinstance(requested, list):
        return jsonify({"error": "Approved folders must be a list"}), 400
    if active_job is not None:
        return jsonify({"error": "Folder approvals cannot change during a scan"}), 409
    validated = []
    for relative in requested:
        path = safe_media_path(relative)
        if not path or not path.is_dir():
            return jsonify({"error": f"Folder is unavailable: {relative}"}), 409
        if any(is_excluded_name(part) for part in Path(relative).parts):
            return jsonify({"error": f"Folder is excluded by safety policy: {relative}"}), 409
        validated.append(relative)
    clean = []
    for relative in sorted(set(validated), key=lambda item: (len(Path(item).parts), item.casefold())):
        if any(Path(relative).is_relative_to(Path(parent)) for parent in clean):
            continue
        clean.append(relative)
    save_config({"approved": clean})
    return jsonify({"ok": True, "approved": clean})


@app.get("/health")
def health():
    try:
        pong = clamd_command("PING")
        healthy = pong == "PONG"
    except OSError:
        healthy = False
        pong = "unavailable"
    return jsonify({"ok": healthy, "clamav": pong, "version": APP_VERSION}), 200 if healthy else 503


@app.get("/api/engine")
def engine():
    try:
        return jsonify({"online": clamd_command("PING") == "PONG", "version": clamd_command("VERSION")})
    except OSError as exc:
        return jsonify({"online": False, "error": str(exc)}), 503


@app.get("/api/status")
def status():
    with job_lock:
        snapshot = active_job.snapshot() if active_job else None
    last_scan = None if snapshot else next(iter(history_rows(limit=1)), None)
    return jsonify({"active": snapshot, "last": last_scan})


@app.get("/api/history")
def history():
    return jsonify({"history": history_rows()})


@app.get("/api/history/<int:scan_id>")
def history_detail(scan_id):
    scan = scan_by_id(scan_id)
    return (jsonify({"scan": scan}), 200) if scan else (jsonify({"error": "Scan not found"}), 404)


@app.post("/api/scans")
def start_scan():
    global active_job
    payload = request.get_json(silent=True) or {}
    root_key = payload.get("root")
    available = approved_paths()
    if not available:
        return jsonify({"error": "No storage folders are approved"}), 409
    if root_key == "__all__":
        label = available[0][0] if len(available) == 1 else f"{len(available)} approved folders"
        root_paths = [path for _, path in available]
    else:
        selected = next(((relative, path) for relative, path in available if relative == root_key), None)
        if not selected:
            return jsonify({"error": "Selected folder is not approved"}), 409
        label = selected[0]
        root_paths = [selected[1]]
    with job_lock:
        if active_job is not None:
            return jsonify({"error": "A scan is already running", "active": active_job.snapshot()}), 409
        with db_connection() as connection:
            cursor = connection.execute(
                """INSERT INTO scans
                (root_key, root_label, started_at, status, scan_roots_json)
                VALUES (?, ?, ?, ?, ?)""",
                (root_key, label, utc_now(), "running", json.dumps([relative for relative, _ in available] if root_key == "__all__" else [root_key])),
            )
            scan_id = cursor.lastrowid
        active_job = ScanJob(scan_id, root_key, label, root_paths)
        threading.Thread(target=run_scan, args=(active_job,), daemon=True).start()
        snapshot = active_job.snapshot()
    return jsonify({"scan": snapshot}), 202


@app.post("/api/scans/<int:scan_id>/cancel")
def cancel_scan(scan_id):
    with job_lock:
        if active_job is None or active_job.scan_id != scan_id:
            return jsonify({"error": "Active scan not found"}), 404
        active_job.cancel_event.set()
        snapshot = active_job.snapshot()
    return jsonify({"scan": snapshot}), 202


@app.get("/api/quarantine")
def quarantine_list():
    return jsonify({"items": quarantine_rows()})


@app.post("/api/quarantine")
def quarantine_file():
    if active_job is not None:
        return jsonify({"error": "Wait for the active scan to finish before quarantining a file"}), 409
    payload = request.get_json(silent=True) or {}
    scan_id = payload.get("scan_id")
    source_text = payload.get("file", "")
    signature = payload.get("signature", "")
    scan = scan_by_id(scan_id) if isinstance(scan_id, int) else None
    if not scan:
        return jsonify({"error": "Verified scan record not found"}), 404
    match = next((item for item in scan["detections"] if item.get("file") == source_text and item.get("signature") == signature), None)
    if not match:
        return jsonify({"error": "Detection is not present in the verified scan record"}), 409
    source = Path(source_text)
    if not allowed_scan_path(source) or not source.is_file():
        return jsonify({"error": "Detected file is unavailable or outside approved folders"}), 409
    size = source.stat().st_size
    digest = file_sha256(source)
    destination = QUARANTINE_DIR / f"{uuid.uuid4().hex}.quarantine"
    shutil.move(str(source), str(destination))
    with db_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO quarantine
            (scan_id, original_path, quarantine_path, signature, sha256, size_bytes, status, quarantined_at)
            VALUES (?, ?, ?, ?, ?, ?, 'quarantined', ?)""",
            (scan_id, source_text, str(destination), signature, digest, size, utc_now()),
        )
        item_id = cursor.lastrowid
    return jsonify({"ok": True, "id": item_id, "sha256": digest}), 201


@app.post("/api/quarantine/<int:item_id>/restore")
def restore_file(item_id):
    with db_connection() as connection:
        row = connection.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,)).fetchone()
    if not row or row["status"] != "quarantined":
        return jsonify({"error": "Quarantined item not found"}), 404
    source = Path(row["quarantine_path"])
    destination = Path(row["original_path"])
    if not allowed_quarantine_path(source) or not source.is_file() or not allowed_restore_path(destination):
        return jsonify({"error": "Restore path validation failed"}), 409
    if destination.exists():
        return jsonify({"error": "Original path already contains a file"}), 409
    if not destination.parent.is_dir():
        return jsonify({"error": "Original parent folder no longer exists"}), 409
    if file_sha256(source) != row["sha256"]:
        return jsonify({"error": "Quarantined file integrity check failed"}), 409
    shutil.move(str(source), str(destination))
    with db_connection() as connection:
        connection.execute("UPDATE quarantine SET status = 'restored', restored_at = ? WHERE id = ?", (utc_now(), item_id))
    return jsonify({"ok": True})


@app.delete("/api/quarantine/<int:item_id>")
def delete_quarantined_file(item_id):
    payload = request.get_json(silent=True) or {}
    if payload.get("confirmation") != "DELETE PERMANENTLY":
        return jsonify({"error": "Permanent deletion confirmation is incorrect"}), 400
    with db_connection() as connection:
        row = connection.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,)).fetchone()
    if not row or row["status"] != "quarantined":
        return jsonify({"error": "Quarantined item not found"}), 404
    path = Path(row["quarantine_path"])
    if not allowed_quarantine_path(path):
        return jsonify({"error": "Quarantine path validation failed"}), 409
    if path.exists():
        path.unlink()
    with db_connection() as connection:
        connection.execute("UPDATE quarantine SET status = 'deleted', deleted_at = ? WHERE id = ?", (utc_now(), item_id))
    return jsonify({"ok": True})


init_db()
