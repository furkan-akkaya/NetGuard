import subprocess
import sys
import time

import pytest

from netguard.jobs import JobLimits, JobRunner
from netguard.store import SCHEMA_VERSION, Store, StoreError


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    s.migrate()
    return s


def _running(store: Store) -> str:
    cap, _ = store.add_capture("x.pcap", "ab" * 32, 10, "pcap")
    analysis = store.create_analysis(cap["id"], {}, "test")
    claimed = store.claim_next()
    assert claimed is not None
    assert claimed["id"] == analysis["id"]
    return str(analysis["id"])


def test_migrate_is_idempotent(store):
    assert store.migrate() == SCHEMA_VERSION
    with store.connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_refuses_a_newer_schema(store):
    with store.transaction() as conn:
        conn.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    with pytest.raises(RuntimeError, match="newer"):
        store.migrate()


def test_claim_is_exclusive(store):
    _running(store)
    assert store.claim_next() is None  # the only job is already running


def test_cancelling_a_running_job_kills_its_worker(store, tmp_path):
    aid = _running(store)
    runner = JobRunner(store, tmp_path, JobLimits(timeout_seconds=30, poll_seconds=0.05))
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    store.cancel_analysis(aid)
    started = time.monotonic()
    assert runner._supervise(proc, aid, started) == "cancelled"
    assert time.monotonic() - started < 5
    assert proc.returncode is not None  # killed, not left running
    assert store.get_analysis(aid)["status"] == "cancelled"


def test_finish_only_applies_to_running_jobs(store):
    aid = _running(store)
    assert store.cancel_analysis(aid)
    assert not store.finish_analysis(aid, "done")  # a late worker cannot resurrect a cancelled job
    assert store.get_analysis(aid)["status"] == "cancelled"


def test_cannot_delete_a_capture_with_active_jobs(store):
    aid = _running(store)
    capture_id = store.get_analysis(aid)["capture_id"]
    with pytest.raises(StoreError, match="cancel"):
        store.delete_capture(capture_id)


def test_missing_capture_file_fails_the_job(store, tmp_path):
    aid = _running(store)
    runner = JobRunner(store, tmp_path / "nothing-here")
    runner._run(store.get_analysis(aid))
    analysis = store.get_analysis(aid)
    assert analysis["status"] == "failed"
    assert "missing" in analysis["error"]


def test_worker_runs_in_process_and_truncates_flows(store, tmp_path):
    from netguard.config import Config, config_to_mapping
    from netguard.lab.scenarios import get
    from netguard.lab.synth import write_pcap
    from netguard.worker import main

    pcap = tmp_path / "scan.pcap"
    write_pcap(pcap, get("syn_scan_1000").build())
    cap, _ = store.add_capture("scan.pcap", "cd" * 32, pcap.stat().st_size, "pcap")
    aid = store.create_analysis(cap["id"], config_to_mapping(Config()), "test")["id"]
    store.claim_next()
    assert main([str(store.path), aid, str(pcap), "--max-stored-flows", "100"]) == 0
    analysis = store.get_analysis(aid)
    assert analysis["status"] == "done"
    assert analysis["flow_count"] == 100
    assert analysis["flows_truncated"]
    assert analysis["alert_count"] == 2


def test_worker_reports_invalid_configuration(store, tmp_path, capsys):
    from netguard.worker import run

    aid = _running(store)
    with store.transaction() as conn:
        conn.execute("UPDATE analyses SET config = ? WHERE id = ?", ('{"nope": {}}', aid))
    assert run(str(store.path), aid, str(tmp_path / "x"), 10) == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_worker_skips_jobs_that_are_no_longer_running(store, tmp_path):
    from netguard.worker import run

    aid = _running(store)
    store.cancel_analysis(aid)
    assert run(str(store.path), aid, str(tmp_path / "x"), 10) == 0
