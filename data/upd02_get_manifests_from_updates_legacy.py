# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests",
# ]
# ///

from pathlib import Path
from ctypes import (windll, cast, wintypes, c_ubyte, c_uint64, byref, c_size_t, POINTER,
                    LittleEndianStructure, Union)
import subprocess
import datetime
import requests
import hashlib
import shutil
import json
import stat
import os
import re

import config

# When run standalone, use legacy config.
if __name__ == '__main__':
    import sys
    import config_legacy
    sys.modules['config'] = config_legacy
    config = config_legacy


# Use the system msdelta.dll for PA19 delta patch support (XP/2003 hotfix format).
_msdelta = windll.msdelta

class _DELTA_INPUT(LittleEndianStructure):
    class _U1(Union):
        _fields_ = [('lpcStart', wintypes.LPVOID), ('lpStart', wintypes.LPVOID)]
    _anonymous_ = ('u1',)
    _fields_ = [('u1', _U1), ('uSize', c_size_t), ('Editable', wintypes.BOOL)]

class _DELTA_OUTPUT(LittleEndianStructure):
    _fields_ = [('lpStart', wintypes.LPVOID), ('uSize', c_size_t)]

_ApplyDeltaB = _msdelta.ApplyDeltaB
_ApplyDeltaB.argtypes = [c_uint64, _DELTA_INPUT, _DELTA_INPUT, POINTER(_DELTA_OUTPUT)]
_ApplyDeltaB.rettype = wintypes.BOOL
_DeltaFree = _msdelta.DeltaFree
_DeltaFree.argtypes = [wintypes.LPVOID]
_DELTA_APPLY_FLAG_ALLOW_PA19 = 0x00000001


def _apply_sfx_delta(base_data: bytes, patch_data: bytes) -> bytes:
    """Apply a PA19 delta patch using the system msdelta.dll."""
    ds = _DELTA_INPUT()
    dd = _DELTA_INPUT()
    dout = _DELTA_OUTPUT()
    ds.lpcStart = cast(base_data, wintypes.LPVOID)
    ds.uSize = len(base_data)
    ds.Editable = False
    dd.lpcStart = cast(patch_data, wintypes.LPVOID)
    dd.uSize = len(patch_data)
    dd.Editable = False
    status = _ApplyDeltaB(_DELTA_APPLY_FLAG_ALLOW_PA19, ds, dd, byref(dout))
    if status == 0:
        raise Exception('ApplyDeltaB failed for SFX delta patch')
    result = bytes((c_ubyte * dout.uSize).from_address(dout.lpStart))
    _DeltaFree(dout.lpStart)
    return result


class UpdateNotFound(Exception):
    pass


class UpdateNotSupported(Exception):
    pass


def search_for_updates(search_terms: str):
    url = 'https://www.catalog.update.microsoft.com/Search.aspx'
    while True:
        html = requests.get(url, {'q': search_terms}).text
        if 'The website has encountered a problem' not in html:
            break
        # Retry...

    if 'We did not find any results' in html:
        raise UpdateNotFound

    # Don't assert single page — legacy updates can have many results.

    p = r'<a [^>]*?onclick=\'goToDetails\("([a-f0-9\-]+)"\);\'[^>]*?>\s*(.*?)\s*</a>'
    matches = re.findall(p, html)

    p2 = r'<input id="([a-f0-9\-]+)" class="flatBlueButtonDownload\b[^"]*?" type="button" value=\'Download\' />'
    assert [uid for uid, title in matches] == re.findall(p2, html)

    return matches


def get_update_download_urls(update_uid: str):
    input_json = [{
        'uidInfo': update_uid,
        'updateID': update_uid
    }]
    url = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
    html = requests.post(url, {'updateIDs': json.dumps(input_json)}).text

    p = r'\ndownloadInformation\[\d+\]\.files\[\d+\]\.url = \'([^\']+)\';'
    return re.findall(p, html)


def get_update(windows_version: str, update_kb: str):
    search_suffix = config.CATALOG_SEARCH_SUFFIXES.get(windows_version, '')
    search_query = f'{update_kb} {search_suffix}'.strip()

    found_updates = search_for_updates(search_query)

    # Filter out Itanium/IA-64 updates.
    filter_regex = r'\bItanium\b|\bia64\b|\bIA-64\b'
    found_updates = [update for update in found_updates if not re.search(filter_regex, update[1], re.IGNORECASE)]

    # Filter to match the target windows version.
    version_patterns = {
        'XP':       r'\bWindows XP\b(?!.*(?:x64|Professional x64))',
        'XP-x64':   r'\bWindows XP\b.*\b(?:x64|Professional x64)\b',
        '2003':     r'\bWindows Server 2003\b(?!.*(?:x64|R2))',
        '2003-x64': r'\bWindows Server 2003\b.*\bx64\b(?!.*\bR2\b)',
        '2003-R2':  r'\bWindows Server 2003 R2\b',
    }

    version_pattern = version_patterns.get(windows_version)
    if version_pattern:
        version_filtered = [u for u in found_updates if re.search(version_pattern, u[1], re.IGNORECASE)]
        if version_filtered:
            found_updates = version_filtered

    if len(found_updates) == 0:
        raise UpdateNotFound

    # If multiple results, try to pick the one that best matches.
    # Prefer "Security Update" or "Update" over "Hotfix".
    if len(found_updates) > 1:
        security_updates = [u for u in found_updates if re.search(r'\bSecurity Update\b', u[1], re.IGNORECASE)]
        if security_updates:
            found_updates = security_updates

    if len(found_updates) > 1:
        # Just pick the first one — the catalog typically sorts by relevance.
        print(f'  WARNING: Multiple updates found for {update_kb} ({windows_version}), picking first: {found_updates[0][1]}')

    update_uid, update_title = found_updates[0]
    return update_uid, update_title


def download_update(windows_version: str, update_kb: str):
    download_url = config.updates_alternative_links.get((windows_version, update_kb))
    if not download_url:
        update_uid, update_title = get_update(windows_version, update_kb)

        download_urls = get_update_download_urls(update_uid)
        if not download_urls:
            raise Exception('Update not found in catalog')

        if len(download_urls) > 1:
            # Prefer the URL that contains the KB number.
            kb_urls = [x for x in download_urls if update_kb.lower() in x.lower()]
            if kb_urls:
                download_urls = kb_urls

        if len(download_urls) > 1:
            print(f'  WARNING: Multiple download URLs for {update_kb}, picking first')

        download_url = download_urls[0]

    local_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
    local_dir.mkdir(parents=True, exist_ok=True)

    local_filename = download_url.split('/')[-1]
    local_path = local_dir.joinpath(local_filename)

    args = ['aria2c', '-x4', '--disable-ipv6', '-d', str(local_dir), '-o', local_filename, '--allow-overwrite=true', download_url]
    subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    return download_url, local_dir, local_path


# https://stackoverflow.com/a/44873382
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def extract_update_files(local_dir: Path, local_path: Path):
    def cab_extract(from_file: Path, to_dir: Path):
        to_dir.mkdir(exist_ok=True)
        args = ['expand.exe', '-r', '-f:*', from_file, to_dir]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    def run_7z_extract(from_file: Path, to_dir: Path):
        to_dir.mkdir(exist_ok=True)
        args = ['7z.exe', 'x', from_file, f'-o{to_dir}', '-y']
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    first_unhandled_extract_dir_num = 1
    next_extract_dir_num = 1

    # Extract main archive.
    extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
    print(f'Extracting {local_path} to {extract_dir}')
    next_extract_dir_num += 1

    with local_path.open('rb') as f:
        first_bytes = f.read(16)

    if first_bytes.startswith(b'MSCF'):
        # CAB file.
        cab_extract(local_path, extract_dir)
    elif first_bytes[:2] == b'MZ':
        # Self-extracting EXE — use 7z.
        run_7z_extract(local_path, extract_dir)
    elif first_bytes.startswith(b'MSWIM'):
        run_7z_extract(local_path, extract_dir)
    else:
        # Try 7z as a fallback for other archive formats.
        try:
            run_7z_extract(local_path, extract_dir)
        except subprocess.CalledProcessError:
            raise Exception(f'Unknown archive format: {first_bytes}')

    local_path.unlink()

    # Extract all files from all cab files until no more cab files can be found.
    while first_unhandled_extract_dir_num < next_extract_dir_num:
        next_unhandled_extract_dir_num = next_extract_dir_num

        for src_extract_dir_num in range(first_unhandled_extract_dir_num, next_extract_dir_num):
            src_extract_dir = local_dir.joinpath(f'_extract_{src_extract_dir_num}')
            for p in src_extract_dir.glob('*.cab'):
                extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
                print(f'Extracting {p} to {extract_dir}')
                next_extract_dir_num += 1
                cab_extract(p, extract_dir)
                p.unlink()

        first_unhandled_extract_dir_num = next_unhandled_extract_dir_num

    # Reconstruct files from SFX delta patches if present.
    # XP/2003 hotfixes are often self-extracting EXEs that 7z extracts as:
    #   _sfx_manifest_  — INI-like file describing the delta chain
    #   _sfx_.dll       — seed/base binary
    #   _sfx_NNNN._p    — PA19 delta patches
    # The manifest [Deltas] section has lines like: "target" = "patch", "base"
    # We reconstruct each target by applying the patch to its base.
    for sfx_extract_dir_num in range(1, next_extract_dir_num):
        sfx_extract_dir = local_dir.joinpath(f'_extract_{sfx_extract_dir_num}')
        manifest_path = sfx_extract_dir.joinpath('_sfx_manifest_')
        if not manifest_path.is_file():
            continue

        print(f'  Reconstructing files from SFX delta patches in {sfx_extract_dir}')
        manifest_text = manifest_path.read_text(encoding='utf-8', errors='replace')

        # Parse [Deltas] section.
        in_deltas = False
        delta_entries = {}  # target -> (patch, base)
        for line in manifest_text.splitlines():
            line = line.strip()
            if line == '[Deltas]':
                in_deltas = True
                continue
            if line.startswith('[') and in_deltas:
                break
            if in_deltas and '=' in line:
                # Format: "target" = "patch", "base"
                parts = [p.strip().strip('"') for p in line.replace('=', ',').split(',')]
                if len(parts) == 3:
                    target, patch, base = parts
                    delta_entries[target] = (patch, base)

        if not delta_entries:
            continue

        # Build a cache of file data for the chain resolution.
        file_cache = {}
        for f in sfx_extract_dir.iterdir():
            if f.is_file() and f.name.startswith('_sfx_'):
                file_cache[f.name] = f.read_bytes()

        def resolve(target):
            """Recursively resolve a target by applying its delta chain."""
            if target in file_cache:
                return file_cache[target]

            if target not in delta_entries:
                raise Exception(f'SFX delta target {target} not found in manifest or files')

            patch_name, base_name = delta_entries[target]
            base_data = resolve(base_name)
            patch_path = sfx_extract_dir.joinpath(patch_name)
            if not patch_path.is_file():
                raise Exception(f'SFX delta patch file not found: {patch_name}')
            patch_data = patch_path.read_bytes()

            result = _apply_sfx_delta(base_data, patch_data)
            file_cache[target] = result
            return result

        # Resolve each target and write the reconstructed file.
        for target in delta_entries:
            try:
                data = resolve(target)
                output_path = sfx_extract_dir.joinpath(target)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(data)
                print(f'    Reconstructed {target} ({len(data)} bytes)')
            except Exception as e:
                print(f'    WARNING: Failed to reconstruct {target}: {e}')

        # Clean up SFX artifacts.
        for f in list(sfx_extract_dir.iterdir()):
            if f.is_file() and f.name.startswith('_sfx_'):
                # Make writable before deleting (some are read-only).
                f.chmod(stat.S_IWRITE)
                f.unlink()

    # Move all extracted files from all folders to the target folder.
    for extract_dir in local_dir.glob('_extract_*'):
        def ignore_files(path, names):
            source_dir = Path(path)
            relative_dir = source_dir.relative_to(extract_dir)
            destination_dir = local_dir.joinpath(relative_dir)

            ignore = []
            for name in names:
                source_file = source_dir.joinpath(name)
                if source_file.is_file():
                    # Ignore files in root folder which have different non-identical copies with the same name.
                    if source_dir == extract_dir:
                        if name in ['update.cat', 'update.mum']:
                           ignore.append(name)
                           continue

                    # Ignore files which already exist as long as they're identical.
                    destination_file = destination_dir.joinpath(name)
                    if destination_file.exists():
                        if not destination_file.is_file():
                            raise Exception(f'A destination item already exists and is not a file: {destination_file}')

                        if sha256sum(source_file) != sha256sum(destination_file):
                            # For legacy updates, duplicate files with different content are more
                            # common. Just keep the first one.
                            print(f'  WARNING: Different file copy exists, keeping first: {destination_file}')

                        ignore.append(name)

            return ignore

        shutil.copytree(extract_dir, local_dir, copy_function=shutil.move, dirs_exist_ok=True, ignore=ignore_files)
        shutil.rmtree(extract_dir, onerror=lambda func, path, exc_info: (os.chmod(path, stat.S_IWRITE), func(path)))


def get_files_from_update(windows_version: str, update_kb: str):
    if update_kb in config.updates_unsupported:
        raise UpdateNotSupported

    print(f'[{update_kb}] Downloading update')

    download_url, local_dir, local_path = download_update(windows_version, update_kb)
    print(f'[{update_kb}] Downloaded {local_path.stat().st_size} bytes from {download_url}')

    print(f'[{update_kb}] Extracting update files')
    try:
        extract_update_files(local_dir, local_path)
    except Exception as e:
        print(f'[{update_kb}] ERROR: Failed to process update')
        print(f'[{update_kb}]        {e}')
        if config.exit_on_first_error:
            raise
        return
    print(f'[{update_kb}] Extracted update files')


def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}')

        for update_kb in updates[windows_version]:
            try:
                get_files_from_update(windows_version, update_kb)
            except UpdateNotSupported:
                print(f'[{update_kb}] WARNING: Skipping unsupported update')
            except UpdateNotFound:
                # Legacy updates are frequently removed from the catalog, so always
                # treat as a warning rather than error.
                print(f'[{update_kb}] WARNING: Update wasn\'t found on the update catalog')
            except Exception as e:
                print(f'[{update_kb}] ERROR: Failed to process update')
                print(f'[{update_kb}]        {e}')
                if config.exit_on_first_error:
                    raise

        print()


if __name__ == '__main__':
    main()
