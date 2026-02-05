# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "signify",
# ]
# ///

from signify.authenticode.signed_file import SignedPEFile
from struct import unpack
from pathlib import Path
from typing import List
import hashlib
import signify
import json
import re

import config

# When run standalone, use legacy config.
if __name__ == '__main__':
    import sys
    import config_legacy
    sys.modules['config'] = config_legacy
    config = config_legacy


file_hashes = {}


def update_info_source(old, new):
    sources = [
        'none',
        'delta',
        'delta+',
        'pe',
        'vt',
        'file',
    ]

    if old is None or sources.index(new) > sources.index(old):
        return new

    return old


def update_file_hashes():
    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in file_hashes:
        file_info_sources = info_sources.setdefault(name, {})

        for file_hash in file_hashes[name]:
            old = file_info_sources.get(file_hash)
            new = file_hashes[name][file_hash]
            file_info_sources[file_hash] = update_info_source(old, new)

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)

    file_hashes.clear()


# https://stackoverflow.com/a/44873382
def hash_sum(filename: Path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    b = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            hash_md5.update(mv[:n])
            hash_sha1.update(mv[:n])
            hash_sha256.update(mv[:n])
    return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()


# returns the requested version information from the given file
#
# Reference: https://stackoverflow.com/a/56266129
import ctypes

def get_file_version_info(pathname: Path, prop_names: List[str],
                          language: int | None = None, codepage: int | None = None):
    class LANGANDCODEPAGE(ctypes.Structure):
        _fields_ = [
            ("wLanguage", ctypes.c_uint16),
            ("wCodePage", ctypes.c_uint16)]

    wstr_file = ctypes.wstring_at(str(pathname.resolve(strict=True)))

    size = ctypes.windll.version.GetFileVersionInfoSizeExW(2, wstr_file, None)
    if size == 0:
        e = ctypes.WinError()
        if e.winerror == 1813:
            return {}
        raise e

    buffer = ctypes.create_string_buffer(size)

    if ctypes.windll.version.GetFileVersionInfoExW(2, wstr_file, None, size, buffer) == 0:
        raise ctypes.WinError()

    value = ctypes.c_void_p(0)
    value_size = ctypes.c_uint(0)

    translations = []

    if language is None and codepage is None:
        ret = ctypes.windll.version.VerQueryValueW(
            buffer, ctypes.wstring_at(R"\VarFileInfo\Translation"),
            ctypes.byref(value), ctypes.byref(value_size))

        if ret == 0:
            e = ctypes.WinError()
            if e.winerror == 1813:
                first_language, first_codepage = None, None
            else:
                raise e
        else:
            lcp = ctypes.cast(value, ctypes.POINTER(LANGANDCODEPAGE))
            first_language, first_codepage = lcp.contents.wLanguage, lcp.contents.wCodePage
            translation = first_language, first_codepage
            translations.append(translation)

        translation = first_language, 1252
        if first_language and translation not in translations:
            translations.append(translation)

        translation = 1033, 1252
        if translation not in translations:
            translations.append(translation)

        translation = 1033, first_codepage
        if first_codepage and translation not in translations:
            translations.append(translation)
    else:
        assert language is not None and codepage is not None
        translation = language, codepage
        translations.append(translation)

    result = {}
    for prop_name in prop_names:
        for language_id, codepage_id in translations:
            translation = "{0:04x}{1:04x}".format(language_id, codepage_id)

            res = ctypes.windll.version.VerQueryValueW(
                buffer, ctypes.wstring_at("\\StringFileInfo\\" + translation + "\\" + prop_name),
                ctypes.byref(value), ctypes.byref(value_size))

            if res == 0:
                e = ctypes.WinError()
                if e.winerror == 1813:
                    continue
                raise e

            prop = ctypes.wstring_at(value.value, value_size.value - 1)
            prop = prop.split('\0', 1)[0]

            result[prop_name] = prop
            break

    return result


# Reference:
# https://signify.readthedocs.io/en/latest/authenticode.html
def get_file_signing_times(pathname: Path):
    signing_times = []
    with open(pathname, 'rb') as f:
        pefile = SignedPEFile(f)
        for signed_data in pefile.iter_embedded_signatures(ignore_parse_errors=False):
            if signed_data.signer_info.countersigner is not None:
                signing_time = signed_data.signer_info.countersigner.signing_time
                if signing_time is None:
                    raise Exception('Countersigner without signing time')
                signing_times.append(signing_time.isoformat().removesuffix('+00:00'))

    return signing_times


def get_processor_architecture(machine_type: int) -> str:
    if machine_type == 332:
        return 'x86'
    elif machine_type == 34404:
        return 'amd64'
    else:
        return str(machine_type)


def scan_pe_file(file_path: Path):
    """Scan a single PE file and return its metadata, or None if not a PE file."""
    size = file_path.stat().st_size

    if size < 0x40:
        return None

    with open(file_path, 'rb') as handle:
        if handle.read(2) != b'MZ':
            return None

        # Get PE offset from DOS header.
        handle.seek(0x3c)
        offset = handle.read(4)
        offset = unpack('<I', offset)[0]

        if size < offset + 0x54:
            return None

        handle.seek(offset)
        # Check if PE signature is valid.
        if handle.read(4) != b'PE\0\0':
            return None

        word = handle.read(2)
        machine_type = unpack('<H', word)[0]

        handle.seek(offset + 8)
        dword = handle.read(4)
        timestamp = unpack('<I', dword)[0]

        handle.seek(offset + 0x50)
        dword = handle.read(4)
        virtual_size = unpack('<I', dword)[0]

    md5, sha1, sha256 = hash_sum(file_path)

    result = {
        'size': size,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
        'machineType': machine_type,
        'timestamp': timestamp,
        'virtualSize': virtual_size,
    }

    version_info = get_file_version_info(file_path, ['FileVersion', 'FileDescription'])

    if version_info.get('FileVersion'):
        result['version'] = version_info['FileVersion']

    if version_info.get('FileDescription'):
        result['description'] = version_info['FileDescription']

    try:
        signing_times = get_file_signing_times(file_path)
        result['signingStatus'] = 'Unknown'  # Verification is too time consuming.
        result['signatureType'] = 'Overlay'
        result['signingDate'] = signing_times
    except signify.exceptions.SignedPEParseError as e:
        if str(e) != 'The PE file does not contain a certificate table.':
            raise
        result['signingStatus'] = 'Unsigned'

    return result


def is_pe_extension(filename: str) -> bool:
    return bool(re.search(r'\.(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)$', filename, re.IGNORECASE))


def parse_extracted_files(manifests_dir: Path, output_dir: Path):
    """Walk all files in the extracted update directory and identify PE files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    pe_files_found = 0

    for file_path in manifests_dir.rglob('*'):
        if not file_path.is_file():
            continue

        filename = file_path.name.lower()

        # Only process files with PE extensions.
        if not is_pe_extension(filename):
            continue

        result = scan_pe_file(file_path)
        if result is None:
            if config.allow_unknown_non_pe_files:
                print(f'  Skipping non-PE file with PE extension: {file_path}')
                continue
            else:
                raise Exception(f'Non-PE file with PE extension: {file_path}')

        pe_files_found += 1

        # Track in file_hashes for info_sources.
        file_hashes_for_filename = file_hashes.setdefault(filename, {})
        old_info_source = file_hashes_for_filename.get(result['sha256'])
        file_hashes_for_filename[result['sha256']] = update_info_source(old_info_source, 'pe')

        # Determine processor architecture from machineType.
        proc_arch = get_processor_architecture(result['machineType'])

        # Build a version string from the file if available.
        version = result.get('version', '0.0.0.0')

        # Generate a synthetic assembly identity name.
        # Use the update_kb from the parent directory.
        update_kb = manifests_dir.name
        assembly_name = f'legacy.{update_kb}.{filename}'

        # Build parsed output compatible with upd05's get_file_details_from_assembly().
        parsed = {
            'assemblyIdentity': {
                'name': assembly_name,
                'version': version,
                'processorArchitecture': proc_arch,
            },
            'files': [{
                'sha256': result['sha256'],
                'sha1': result['sha1'],
                'attributes': {
                    'name': filename,
                },
                'fileInfo': result,
            }],
        }

        # Write one JSON per unique (filename, hash) pair to avoid overwrites.
        output_filename = f'{assembly_name}.{result["sha256"][:8]}.json'
        output_path = output_dir.joinpath(output_filename)
        with open(output_path, 'w') as f:
            json.dump(parsed, f, indent=4)

    return pe_files_found


def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}:')

        for update_kb in updates[windows_version]:
            manifests_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
            if manifests_dir.is_dir():
                output_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
                pe_count = parse_extracted_files(manifests_dir, output_dir)
                print(f'  {update_kb}: {pe_count} PE files found')

    update_file_hashes()


if __name__ == '__main__':
    main()
