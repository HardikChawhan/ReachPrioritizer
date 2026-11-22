"""Safe ZIP handling: path traversal, symlink, zip-bomb and size protection."""
from __future__ import annotations

import logging
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict

from app.config import (
    ALLOWED_EXTRACT_EXTENSIONS,
    MAX_COMPRESSION_RATIO,
    MAX_FILES_IN_ZIP,
    MAX_SINGLE_FILE_SIZE,
    MAX_UNCOMPRESSED_SIZE,
)

logger = logging.getLogger(__name__)


class UploadError(Exception):
    """Raised when an uploaded archive is rejected."""


def is_safe_member(name: str) -> bool:
    """Reject absolute paths, drive letters and any '..' component."""
    if not name or name.startswith(("/", "\\")) or "\x00" in name:
        return False
    norm = name.replace("\\", "/")
    if len(norm) > 1 and norm[1] == ":":
        return False
    return all(part not in ("..",) for part in PurePosixPath(norm).parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def inspect_zip(zip_path: Path) -> Dict[str, int]:
    """Validate an archive without extracting it. Returns counts for the project record."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise UploadError("Invalid or corrupt ZIP file") from exc
    if len(infos) > MAX_FILES_IN_ZIP:
        raise UploadError(f"ZIP contains {len(infos)} entries (limit {MAX_FILES_IN_ZIP})")
    total = 0
    source_files = 0
    for info in infos:
        if not is_safe_member(info.filename):
            raise UploadError(f"ZIP contains an unsafe path: {info.filename!r}")
        if info.is_dir():
            continue
        total += info.file_size
        if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_COMPRESSION_RATIO and info.file_size > 1024 * 1024:
            raise UploadError(f"Suspicious compression ratio for {info.filename!r} (possible zip bomb)")
        if Path(info.filename).suffix.lower() in ALLOWED_EXTRACT_EXTENSIONS and "node_modules/" not in info.filename.replace("\\", "/"):
            source_files += 1
    if total > MAX_UNCOMPRESSED_SIZE:
        raise UploadError(f"Archive expands to {total // (1024 * 1024)} MB (limit {MAX_UNCOMPRESSED_SIZE // (1024 * 1024)} MB)")
    if source_files == 0:
        raise UploadError("ZIP does not contain any JavaScript/TypeScript source files")
    return {"entries": len(infos), "source_files": source_files, "uncompressed_bytes": total}


def extract_project_zip(zip_path: Path, target_dir: Path) -> Path:
    """Extract only source/config files, enforcing every safety limit during extraction."""
    inspect_zip(zip_path)
    target_dir.mkdir(parents=True, exist_ok=True)
    root = target_dir.resolve()
    written = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or _is_symlink(info):
                continue
            name = info.filename.replace("\\", "/")
            if "/node_modules/" in f"/{name}" or Path(name).suffix.lower() not in ALLOWED_EXTRACT_EXTENSIONS:
                continue
            if info.file_size > MAX_SINGLE_FILE_SIZE:
                logger.info("Skipping large file %s (%d bytes)", name, info.file_size)
                continue
            dest = (target_dir / name).resolve()
            if root not in dest.parents:
                raise UploadError(f"Path escapes extraction directory: {name!r}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            remaining = MAX_SINGLE_FILE_SIZE
            with zf.open(info, "r") as src, open(dest, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    written += len(chunk)
                    if remaining < 0 or written > MAX_UNCOMPRESSED_SIZE:
                        raise UploadError("Archive content exceeds the allowed size (possible zip bomb)")
                    out.write(chunk)
    return target_dir


def single_root(target_dir: Path) -> Path:
    """If the archive wraps everything in one folder, analyze that folder."""
    entries = [p for p in target_dir.iterdir() if not p.name.startswith((".", "__MACOSX"))]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return target_dir


__all__ = ["UploadError", "is_safe_member", "inspect_zip", "extract_project_zip", "single_root"]
