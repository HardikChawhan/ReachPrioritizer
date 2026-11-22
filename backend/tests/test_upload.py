"""ZIP safety."""
import io
import stat
import zipfile

import pytest

from app.core.upload_handler import UploadError, extract_project_zip, inspect_zip, is_safe_member, single_root


def _zip(tmp_path, entries, name="p.zip"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for e in entries:
            if isinstance(e, zipfile.ZipInfo):
                zf.writestr(e, "target")
            else:
                zf.writestr(*e)
    p = tmp_path / name
    p.write_bytes(buf.getvalue())
    return p


def test_safe_member_names():
    assert is_safe_member("src/server.js")
    assert is_safe_member("app/routes/users.js")
    assert not is_safe_member("../etc/passwd")
    assert not is_safe_member("foo/../../bar.js")
    assert not is_safe_member("/abs/path.js")
    assert not is_safe_member("C:/windows/x.js")
    assert not is_safe_member("..\\evil.js")


def test_extracts_sources_only_and_unwraps_single_folder(tmp_path):
    z = _zip(tmp_path, [("app/src/index.js", "console.log(1)"), ("app/package.json", "{}"),
                        ("app/logo.png", "x"), ("app/node_modules/x/index.js", "1")])
    out = extract_project_zip(z, tmp_path / "out")
    root = single_root(out)
    assert root.name == "app"
    assert (root / "src" / "index.js").exists()
    assert (root / "package.json").exists()
    assert not (root / "logo.png").exists()
    assert not (root / "node_modules").exists()


def test_rejects_traversal(tmp_path):
    z = _zip(tmp_path, [("../evil.js", "x"), ("a.js", "1")])
    with pytest.raises(UploadError):
        inspect_zip(z)


def test_skips_symlinks(tmp_path):
    link = zipfile.ZipInfo("src/link.js")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    z = _zip(tmp_path, [link, ("src/real.js", "1")])
    out = extract_project_zip(z, tmp_path / "out")
    assert (out / "src" / "real.js").exists()
    assert not (out / "src" / "link.js").exists()


def test_rejects_archive_without_sources(tmp_path):
    z = _zip(tmp_path, [("readme.txt", "hi")])
    with pytest.raises(UploadError):
        inspect_zip(z)


def test_rejects_zip_bomb(tmp_path):
    z = _zip(tmp_path, [("big.js", "a" * (50 * 1024 * 1024)), ("x.js", "1")])
    with pytest.raises(UploadError):
        inspect_zip(z)


def test_rejects_corrupt_zip(tmp_path):
    p = tmp_path / "bad.zip"
    p.write_bytes(b"not a zip")
    with pytest.raises(UploadError):
        inspect_zip(p)
