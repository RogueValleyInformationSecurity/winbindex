# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "cabarchive",
# ]
# ///

from pathlib import Path
from struct import unpack
import subprocess
import json
import stat
import sys
import os
import re

from extract_data_from_pe_files import extract_data_from_pe_files
import config

# When run standalone, use legacy config.
if __name__ == '__main__':
    import config_legacy
    sys.modules['config'] = config_legacy
    config = config_legacy

# To get data from a Windows XP or Server 2003 ISO file, use:
#
# mkdir C:\w
# cd C:\w
# 7z.exe x C:\path\to\windows.iso -oC:\w
#
# XP ISOs have an i386\ directory (x86) or amd64\ directory (x64).
#
# Embedded CABs (driver.cab, sp2.cab, etc.) need extraction:
#   expand.exe -r -f:* file.cab output_dir\
#
# Compressed single-file cabinets (*.dl_, *.ex_, *.sy_, etc.) are
# expanded automatically by this script before PE analysis.
#
# Then point this script at the resulting folder.
# Note: Prefix the path with \\?\:
# \\?\C:\w
# In order to add support for long paths to sigcheck.
#
# Finally, run upd05_group_by_filename.py to aggregate the results.


MSCF_MAGIC = b'MSCF'           # Microsoft Cabinet Format
SZDD_MAGIC = b'SZDD\x88\xf0\x27\x33'  # SZDD/KWAJ compressed


def get_cabinet_filename(filepath):
    """Read the real filename from an MSCF or SZDD cabinet header.

    Returns the real filename (str), or None if the file is not a cabinet.
    """
    with open(filepath, 'rb') as f:
        header = f.read(64)

    if header[:4] == MSCF_MAGIC:
        return _get_mscf_filename(filepath)
    elif header[:8] == SZDD_MAGIC:
        return _get_szdd_filename(filepath, header)
    return None


def _get_mscf_filename(filepath):
    """Extract the first filename from an MSCF cabinet."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # MSCF header: offset 16 = coffFiles (u32 LE) — points to first CFFILE entry.
    coff_files = unpack('<I', data[16:20])[0]

    # CFFILE fixed header is 16 bytes, followed by null-terminated szName.
    name_offset = coff_files + 16
    name_end = data.index(b'\x00', name_offset)
    name = data[name_offset:name_end].decode('ascii', errors='replace')
    # Strip any directory prefix (some cabinets embed paths).
    return name.split('\\')[-1].split('/')[-1]


def _get_szdd_filename(filepath, header):
    """Reconstruct the filename for an SZDD-compressed file.

    Byte 9 of the SZDD header contains the missing last character of the
    original extension. Replace the trailing '_' in the filename with it.
    """
    missing_char = chr(header[9])
    if missing_char == '\x00':
        return None  # No recovery info
    name = filepath.name
    if name.endswith('_'):
        return name[:-1] + missing_char
    return None


def expand_cabinet_python(filepath, target):
    """Expand an MSCF cabinet using the cabarchive library."""
    import cabarchive
    with open(filepath, 'rb') as f:
        data = f.read()
    arc = cabarchive.CabArchive(data)
    # Take the first (and usually only) file in the cabinet.
    for cff in arc.values():
        target.write_bytes(cff.buf)
        return
    raise ValueError('Empty cabinet')


def expand_cabinet_fallback(filepath, target):
    """Expand a cabinet file using expand.exe (handles LZX/Quantum/SZDD)."""
    # expand.exe doesn't understand \\?\ long-path prefix, strip it.
    src = str(filepath)
    dst = str(target)
    if src.startswith('\\\\?\\'):
        src = src[4:]
    if dst.startswith('\\\\?\\'):
        dst = dst[4:]
    subprocess.run(
        [R'C:\WINDOWS\system32\expand.exe', src, dst],
        check=True, capture_output=True,
    )


def expand_compressed_files(folder):
    """Expand cabinet-compressed _-suffix files in-place."""
    count = 0
    errors = 0
    for filepath in sorted(folder.rglob('*')):
        if not filepath.is_file() or not filepath.name.endswith('_'):
            continue

        real_name = get_cabinet_filename(filepath)
        if real_name is None:
            continue  # Not a cabinet file, leave it

        target = filepath.parent / real_name
        if target.exists():
            # Already expanded (e.g. by a prior run); remove the compressed copy.
            filepath.unlink()
            count += 1
            continue

        try:
            expand_cabinet_python(filepath, target)
        except Exception:
            try:
                expand_cabinet_fallback(filepath, target)
            except Exception as e:
                print(f'  Warning: failed to expand {filepath.name}: {e}')
                errors += 1
                continue

        filepath.unlink()
        count += 1

    print(f'  Expanded {count} compressed files' + (f' ({errors} errors)' if errors else ''))


# https://stackoverflow.com/a/1151705
class hashabledict(dict):
    def __hash__(self):
        return hash(tuple(sorted(self.items())))


def main(folder: Path, windows_version: str, iso_sha256: str, release_date: str, output_name: str = None):
    assert windows_version in config.LEGACY_VERSIONS, f'Invalid version: {windows_version}'
    assert re.match(r'^[A-Fa-f0-9]{64}$', iso_sha256)
    assert re.match(r'^\d{4}-\d{2}-\d{2}$', release_date)
    assert str(folder).startswith('\\\\?\\'), 'Prefix dir with \\\\?\\ for long paths'

    if output_name is None:
        output_name = windows_version

    print('Expanding compressed files...')
    expand_compressed_files(folder)

    result_files = set()
    pe_file_hashes = {}

    # XP/2003 ISOs have a flat structure with i386/amd64 at the top level.
    # Exclude dirs that contain duplicate/cached copies.
    excluded_paths = [
        R'i386\dllcache',
        R'i386\Driver Cache',
        R'i386\ServicePackFiles',
        R'amd64\dllcache',
        R'amd64\Driver Cache',
        R'amd64\ServicePackFiles',
        R'SUPPORT',
        R'VALUEADD',
        R'DOCS',
    ]
    excluded_paths = [x.lower() + '\\' for x in excluded_paths]

    def path_filter_callback(filename_relative: Path):
        filename_relative_lower = str(filename_relative).lower()
        if any(filename_relative_lower.startswith(excluded_path) for excluded_path in excluded_paths):
            return None

        return filename_relative

    def callback(filename: str, result_item):
        result_files.add(hashabledict(result_item))

        name = filename.split('\\')[-1].lower()
        if (re.search(r'\.(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)$', name)):
            pe_file_hashes.setdefault(name, set()).add(result_item['sha256'])

    extract_data_from_pe_files(folder, callback, path_filter_callback=path_filter_callback, verbose=True)

    result = {
        'windowsVersion': windows_version,
        'windowsIsoSha256': iso_sha256.lower(),
        'windowsReleaseDate': release_date,
        'files': list(result_files),
    }

    print('Writing results...')

    output_dir = config.out_path.joinpath('from_iso')
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir.joinpath(output_name + '.json'), 'w') as f:
        json.dump(result, f, indent=4)

    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in pe_file_hashes:
        for file_hash in pe_file_hashes[name]:
            info_sources.setdefault(name, {})[file_hash] = 'file'

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)


if __name__ == '__main__':
    if len(sys.argv) not in (5, 6):
        exit(f'Usage: {sys.argv[0]} folder windows_version iso_sha256 release_date_yyyy_mm_dd [output_name]')

    folder, windows_version, iso_sha256, release_date = sys.argv[1:5]
    output_name = sys.argv[5] if len(sys.argv) == 6 else None
    main(Path(folder), windows_version, iso_sha256, release_date, output_name)
