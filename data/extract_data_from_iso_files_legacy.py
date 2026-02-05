# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

from pathlib import Path
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
# Compressed files like *.dl_, *.ex_, *.sy_ need decompression:
#   expand.exe file.dl_ file.dll
#
# Embedded CABs (driver.cab, sp2.cab, etc.) need extraction:
#   expand.exe -r -f:* file.cab output_dir\
#
# Then point this script at the resulting folder.
# Note: Prefix the path with \\?\:
# \\?\C:\w
# In order to add support for long paths to sigcheck.
#
# Finally, run upd05_group_by_filename.py to aggregate the results.


# https://stackoverflow.com/a/1151705
class hashabledict(dict):
    def __hash__(self):
        return hash(tuple(sorted(self.items())))


def main(folder: Path, windows_version: str, iso_sha256: str, release_date: str):
    assert windows_version in config.LEGACY_VERSIONS, f'Invalid version: {windows_version}'
    assert re.match(r'^[A-Fa-f0-9]{64}$', iso_sha256)
    assert re.match(r'^\d{4}-\d{2}-\d{2}$', release_date)
    assert str(folder).startswith('\\\\?\\'), 'Prefix dir with \\\\?\\ for long paths'

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
    with open(output_dir.joinpath(windows_version + '.json'), 'w') as f:
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
    if len(sys.argv) != 5:
        exit(f'Usage: {sys.argv[0]} folder windows_version iso_sha256 release_date_yyyy_mm_dd')

    folder, windows_version, iso_sha256, release_date = sys.argv[1:5]
    main(Path(folder), windows_version, iso_sha256, release_date)
