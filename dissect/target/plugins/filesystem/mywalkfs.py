from collections.abc import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import LayerFilesystemEntry
from dissect.target.helpers.magic import from_entry
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

SUID_IDENTIFIER = 0o4000

WalkFileSystemRecord = TargetRecordDescriptor(
    "filesystem/newentry",
    [
        ("datetime", "atime"),
        ("datetime", "mtime"),
        ("datetime", "ctime"),
        ("datetime", "btime"),
        ("varint", "ino"),
        ("path", "path"),
        ("filesize", "size"),
        ("uint32", "mode"),
        ("uint32", "uid"),
        ("uint32", "gid"),
        ("string", "mimetype"),
        ("boolean", "is_suid"),
        ("string", "type"),
        ("string[]", "attr"),
        ("string[]", "fs_types"),
        ("string[]", "volume_identifiers"),
    ],
)

class MyWalkPlugin(Plugin):
    """Plugin to recursively walk through the filesystem and return file information."""
    def check_compatible(self) -> None:
        if not len(self.target.fs.mounts):
            raise UnsupportedPluginError("No filesystems found on target")


    @export(record=WalkFileSystemRecord)
    def mywalkfs(
            self,
            walkfs_path: str = "/",
            check_mime: bool = True,
    ) -> Iterator[WalkFileSystemRecord]:
        """Recursively walk through the filesystem and return file information.

        Args:
            walkfs_path: The path on the target to start walking from. Defaults to "/".
            check_mime: Whether to check the MIME type of files. Defaults to True.
        Returns:
            Iterator yields ``walkfsRecord``.
        """


        for file in self.target.fs.recurse(walkfs_path):
            stat = file.lstat() #lstat because we want info about the symlink not the target

            mimetype = None #because dirs and symlinks dont have mime type
            type = "Unknown"
            if file.is_symlink():
                type = "Symlink"
            elif file.is_dir():
                type = "Directory"
            elif file.is_file():
                if check_mime:
                    mimetype = from_entry(file, mime=True)
                type = "File"

            try:
                attr = file.attr() #returns a dict of [string, byte] not quite what i need but im not sure because some functions just return none
            except Exception:
                attr = None

            fs_types = []
            volume_identifiers = []
            if isinstance(file, LayerFilesystemEntry): #layered file system
                for layer in file.fs.layers:
                    fs_types.append(layer.__type__)
                    volume_identifiers.append(layer.identifier)
            else:
                fs_types = [file.fs.__type__]
                volume_identifiers = [file.fs.identifier]


            yield WalkFileSystemRecord(
                atime=stat.st_atime,
                mtime=stat.st_mtime,
                ctime=stat.st_ctime,
                btime=stat.st_birthtime,
                ino=stat.st_ino,
                path=self.target.fs.path(file.path),
                size=stat.st_size,
                mode=stat.st_mode,
                uid=stat.st_uid,
                gid=stat.st_gid,
                mimetype=mimetype,
                is_suid=bool(stat.st_mode & SUID_IDENTIFIER),
                type=type,
                attr=attr,
                fs_types=fs_types,
                volume_identifiers=volume_identifiers,
                _target=self.target,
            )


