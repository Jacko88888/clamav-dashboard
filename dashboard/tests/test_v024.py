import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TEST_ROOT = tempfile.TemporaryDirectory()
BASE = Path(TEST_ROOT.name)
os.environ["DATA_DIR"] = str(BASE / "data")
os.environ["MEDIA_ROOT"] = str(BASE / "media")
os.environ["HOST_DATA_ROOT"] = str(BASE / "host-data")
(BASE / "media").mkdir()
(BASE / "host-data").mkdir()

APP_SOURCE = Path(os.getenv("APP_SOURCE", "/app/app.py"))
spec = importlib.util.spec_from_file_location("dashboard_app", APP_SOURCE)
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class Version024Tests(unittest.TestCase):
    def setUp(self):
        dashboard.MEDIA_ROOT = BASE / "media"
        dashboard.HOST_DATA_ROOT = BASE / "host-data"
        dashboard.DATA_DIR = BASE / "data"
        dashboard.QUARANTINE_DIR = dashboard.DATA_DIR / "quarantine"
        dashboard.DB_PATH = dashboard.DATA_DIR / "clamav-dashboard.db"
        dashboard.CONFIG_PATH = dashboard.DATA_DIR / "config.json"
        dashboard.init_db()

    def test_exclusions_are_exact_not_substring_based(self):
        self.assertTrue(dashboard.is_excluded_name("AppData"))
        self.assertTrue(dashboard.is_excluded_name("backup"))
        self.assertTrue(dashboard.is_excluded_name("machine.qcow2"))
        self.assertFalse(dashboard.is_excluded_name("Restore Photos"))
        self.assertFalse(dashboard.is_excluded_name("Docker Course"))
        self.assertFalse(dashboard.is_excluded_name("database notes"))

    def test_marker_discovery_skips_an_unreadable_cloud_path(self):
        healthy = dashboard.MEDIA_ROOT / "healthy-disk"
        locked = dashboard.MEDIA_ROOT / "onedrive-example"
        healthy.mkdir(exist_ok=True)
        locked.mkdir(exist_ok=True)
        (healthy / ".zimaos_storage.json").write_text("{}", encoding="utf-8")
        original_scandir = os.scandir

        def guarded_scandir(path):
            if Path(path) == locked:
                raise OSError(5, "Input/output error")
            return original_scandir(path)

        with mock.patch.object(dashboard.os, "scandir", side_effect=guarded_scandir):
            roots = dashboard.discover_disk_roots()
        self.assertIn("healthy-disk", {item["path"] for item in roots})

    def test_internal_data_disk_has_a_stable_logical_path(self):
        documents = dashboard.HOST_DATA_ROOT / "Documents"
        documents.mkdir(exist_ok=True)
        self.assertEqual(dashboard.relative_storage_path(documents), "ZimaOS-HD/Documents")
        self.assertEqual(dashboard.safe_storage_path("ZimaOS-HD/Documents"), documents)
        self.assertIn("ZimaOS-HD", {item["path"] for item in dashboard.discover_disk_roots()})

    def test_skipped_directories_are_recorded_and_benign_names_are_scanned(self):
        root = dashboard.MEDIA_ROOT / "scan-disk"
        backup = root / "backup"
        benign = root / "Restore Photos"
        backup.mkdir(parents=True, exist_ok=True)
        benign.mkdir(parents=True, exist_ok=True)
        (backup / "hidden.txt").write_text("hidden", encoding="utf-8")
        visible = benign / "visible.txt"
        visible.write_text("visible", encoding="utf-8")
        job = dashboard.ScanJob(1, "scan-disk", "scan-disk", [root])
        files = dashboard.enumerate_files(job)
        self.assertEqual([path for path, _ in files], [visible])
        self.assertTrue(any(item.get("kind") == "directory" and item.get("folder") == str(backup)
                            for item in job.skipped_details))

    def test_quarantine_restore_preserves_recorded_mode_and_owner(self):
        root = dashboard.MEDIA_ROOT / "ownership-disk"
        root.mkdir(exist_ok=True)
        source = root / "sample.txt"
        source.write_text("safe test content", encoding="utf-8")
        source.chmod(0o640)
        signature = "Unit-Test-Signature"
        detection = {"scan_id": 99, "file": str(source), "signature": signature, "size": source.stat().st_size}
        dashboard.save_config({"approved": ["ownership-disk"]})
        with dashboard.db_connection() as connection:
            connection.execute(
                """INSERT INTO scans
                (id, root_key, root_label, started_at, finished_at, status, detections_json, scan_roots_json)
                VALUES (99, ?, ?, ?, ?, 'infected', ?, ?)""",
                ("ownership-disk", "ownership-disk", dashboard.utc_now(), dashboard.utc_now(),
                 json.dumps([detection]), json.dumps(["ownership-disk"])),
            )
        client = dashboard.app.test_client()
        headers = {"X-Dashboard-Token": dashboard.ACTION_TOKEN}
        response = client.post("/api/quarantine", json=detection, headers=headers)
        self.assertEqual(response.status_code, 201)
        item_id = response.get_json()["id"]
        with dashboard.db_connection() as connection:
            row = connection.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,)).fetchone()
        self.assertEqual(row["original_uid"], os.getuid())
        self.assertEqual(row["original_gid"], os.getgid())
        self.assertEqual(row["original_mode"], 0o640)
        Path(row["quarantine_path"]).chmod(0o600)
        response = client.post(f"/api/quarantine/{item_id}/restore", headers=headers)
        self.assertEqual(response.status_code, 200)
        restored = source.stat()
        self.assertEqual(stat.S_IMODE(restored.st_mode), 0o640)
        self.assertEqual(restored.st_uid, os.getuid())
        self.assertEqual(restored.st_gid, os.getgid())


if __name__ == "__main__":
    unittest.main()
