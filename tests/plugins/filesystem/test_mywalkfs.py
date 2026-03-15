from __future__ import annotations

import stat
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import LayerFilesystem, VirtualFile
from dissect.target.helpers import fsutil
from dissect.target.plugins.filesystem.mywalkfs import MyWalkPlugin

if TYPE_CHECKING:
    from dissect.target import Target
    from dissect.target.filesystem import VirtualFilesystem


@pytest.fixture
def target_mywalkfs(target_unix: Target, fs_unix: VirtualFilesystem) -> Target:
    target_unix.fs.mount("/", fs_unix)
    target_unix.add_plugin(MyWalkPlugin)

    # Basic attributes file.
    vfile = VirtualFile(target_unix.fs, "binary", BytesIO(b"test string"))
    vfile.lstat = Mock()
    vfile.lstat.return_value = fsutil.stat_result(
        [
            stat.S_IFREG | stat.S_ISUID | 0o644,
            12345,
            0,
            1,
            1000,
            1000,
            8192,
            1709300000,
            1709301000,
            1709302000,
            None,
            None,
            None,
            None,
            None,
            None,
            4096,
            16,
            0,
            0,
            0,
            1709200000,
        ]
    )
    target_unix.fs.map_file_entry("/path/to/suid/binary", vfile)

    # Symlink.
    target_unix.fs.symlink("/path/to/suid/binary", "/symlinkfile")

    # Directory tree.
    target_unix.fs.map_file_fh("/path/to/directory/file", BytesIO(b"test string"))

    # Layered filesystem.
    layered_fs = LayerFilesystem()
    layer_1 = layered_fs.append_layer()
    layer_1.map_file_fh("/file_in_layer_1", BytesIO(b"test string"))
    layer_2 = layered_fs.append_layer()
    layer_2.map_file_fh("/file_in_layer_2", BytesIO(b"test string"))
    target_unix.fs.mount("/layered", layered_fs)

    return target_unix


def test_basic_attributes_file(target_mywalkfs: Target) -> None:
    """Verify mywalkfs preserves stat-derived timestamps, ownership, and SUID metadata for files."""
    results = list(target_mywalkfs.mywalkfs())

    record = results[7]

    assert record.atime == datetime.fromtimestamp(1709300000, tz=timezone.utc)
    assert record.mtime == datetime.fromtimestamp(1709301000, tz=timezone.utc)
    assert record.ctime == datetime.fromtimestamp(1709302000, tz=timezone.utc)
    assert record.btime == datetime.fromtimestamp(1709200000, tz=timezone.utc)

    assert record.ino == 12345
    assert record.size == 8192

    assert record.mode == (stat.S_IFREG | stat.S_ISUID | 0o644)
    assert record.uid == 1000
    assert record.gid == 1000

    assert record.is_suid


def test_symlink(target_mywalkfs: Target) -> None:
    """Verify mywalkfs reports symlink entries with the expected record type."""
    results = list(target_mywalkfs.mywalkfs())
    record = results[10]

    assert record.type == "Symlink"


def test_directory(target_mywalkfs: Target) -> None:
    """Verify mywalkfs emits directory records for nested directory paths."""
    results = list(target_mywalkfs.mywalkfs())
    assert results[4].type == "Directory"
    assert results[5].type == "Directory"
    assert results[8].type == "Directory"


def test_layered_filesystem(target_mywalkfs: Target) -> None:
    """Verify mywalkfs includes filesystem layering metadata for layered filesystems."""
    results = list(target_mywalkfs.mywalkfs())

    assert results[3].fs_types == ["virtual", "virtual", "virtual"]
    assert len(results[3].volume_identifiers) == 3
