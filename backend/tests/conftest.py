"""Test configuration: isolated database + upload dir per test session."""
import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="rp_test_")
os.environ.setdefault("RP_DB_PATH", str(Path(_tmp) / "test.db"))
os.environ.setdefault("RP_UPLOAD_DIR", str(Path(_tmp) / "uploads"))
os.environ.setdefault("RP_MODEL", "tfidf")
os.environ.setdefault("RP_ENABLE_DEPCHECK", "0")  # no network in tests; the feature test mocks OSV

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
