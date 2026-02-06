# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "isal",
#   "orjson",
#   "pysocks",
#   "requests",
#   "signify",
# ]
# ///
"""Local batch runner for the legacy pipeline.
Processes KBs from updates_xp_2003.json, commits and pushes as it goes.

Usage: uv run --script _run_local.py
"""

import sys
import config_legacy
sys.modules['config'] = config_legacy
config = config_legacy

from pathlib import Path
from datetime import datetime
import subprocess
import json
import shutil
import stat
import os
import time

from upd02_get_manifests_from_updates_legacy import main as upd02_main, UpdateNotFound, UpdateNotSupported, get_files_from_update
from upd03_parse_pe_files_legacy import main as upd03_main, parse_extracted_files, update_file_hashes, file_hashes
from upd05_group_by_filename import main as upd05_group_by_filename

# Try to import VT module; skip VT step if pymultitor isn't running.
try:
    from upd04_get_virustotal_data import (
        create_virustotal_urllib_session,
        get_virustotal_data_for_file,
        lookup_virustotal_bulk_hashes_exist,
    )
    HAS_VT = True
except ImportError:
    HAS_VT = False


def git(*args):
    return subprocess.run(
        ['git', '-C', str(config.out_path)] + list(args),
        capture_output=True, text=True
    )


def commit_and_push(message):
    git('add', '-A')
    # Check if there are changes
    result = git('diff-index', '--quiet', '--cached', 'HEAD')
    if result.returncode == 0:
        print('  No changes to commit')
        return
    git('commit', '-m', message)
    result = git('push', '-u', 'origin', 'gh-pages-legacy')
    if result.returncode != 0:
        print(f'  Push failed: {result.stderr}')
    else:
        print(f'  Committed and pushed: {message}')


def try_fetch_vt_data(parsed_dir):
    """Fetch VirusTotal data for parsed PE files. Returns number of VT results fetched."""
    if not HAS_VT:
        return 0

    vt_dir = config.out_path / 'virustotal'
    vt_dir.mkdir(parents=True, exist_ok=True)

    # Collect SHA256 hashes from parsed JSON files.
    hashes_to_fetch = []
    if not parsed_dir.is_dir():
        return 0

    for json_file in parsed_dir.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)
            sha256 = data.get('sha256')
            name = json_file.stem
            if sha256 and not vt_dir.joinpath(f'{sha256}.json').is_file():
                hashes_to_fetch.append((name, sha256))
        except (json.JSONDecodeError, KeyError):
            continue

    if not hashes_to_fetch:
        return 0

    # Try to connect to pymultitor proxy.
    try:
        session = create_virustotal_urllib_session()
        # Quick connectivity test.
        session.get('https://www.virustotal.com/', verify=False, timeout=10)
    except Exception:
        print('  VT: pymultitor proxy not available, skipping')
        return 0

    fetched = 0
    retry_sleep = 1
    for name, sha256 in hashes_to_fetch:
        for attempt in range(5):
            try:
                result = get_virustotal_data_for_file(session, sha256, vt_dir)
            except Exception as e:
                print(f'  VT: Error fetching {sha256} ({name}): {e}')
                result = 'exception'
                break

            if result != 'retry':
                retry_sleep = 1
                break

            retry_sleep = min(retry_sleep * 2, 300)
            print(f'  VT: Rate limited, waiting {retry_sleep}s before retry ({name})')
            time.sleep(retry_sleep)
        else:
            print(f'  VT: Gave up on {sha256} ({name}) after 5 attempts')
            continue

        if result in ['ok', 'exists']:
            fetched += 1

    return fetched


def main():
    # Ensure the gh-pages repo has an initial commit.
    result = git('rev-parse', 'HEAD')
    if result.returncode != 0:
        # Create initial empty commit.
        git('commit', '--allow-empty', '-m', 'Initial commit')
        git('push', '-u', 'origin', 'gh-pages-legacy')

    # Load the full update list.
    source = Path(__file__).parent / 'updates_xp_2003.json'
    with open(source) as f:
        all_updates = json.load(f)

    # Load already-processed KBs.
    last_path = config.out_path / 'updates_last.json'
    if last_path.is_file():
        with open(last_path) as f:
            last_updates = json.load(f)
    else:
        last_updates = {}

    done_pairs = {(ver, kb) for ver in last_updates for kb in last_updates[ver]}

    # Build a flat list of (version, kb) to process.
    todo = []
    for version in all_updates:
        for kb, info in all_updates[version].items():
            if (version, kb) not in done_pairs:
                todo.append((version, kb, info))

    print(f'{len(done_pairs)} version/KB pairs already processed, {len(todo)} entries remaining\n')

    if not todo:
        print('Nothing to do!')
        return

    batch_count = 0
    for version, kb, info in todo:
        print(f'=== [{version}] {kb}: {info["title"]} ===')

        # Write a single-KB updates.json for the pipeline.
        single = {version: {kb: info}}
        updates_path = config.out_path / 'updates.json'
        with open(updates_path, 'w') as f:
            json.dump(single, f, indent=4)

        # Step 1: Download and extract.
        try:
            get_files_from_update(version, kb)
        except UpdateNotFound:
            print(f'  WARNING: Not found on catalog, skipping')
            _mark_done(last_updates, all_updates, version, kb, last_path)
            continue
        except UpdateNotSupported:
            print(f'  WARNING: Unsupported, skipping')
            _mark_done(last_updates, all_updates, version, kb, last_path)
            continue
        except Exception as e:
            print(f'  ERROR: {e}')
            _mark_done(last_updates, all_updates, version, kb, last_path)
            continue

        # Step 2: Parse PE files.
        manifests_dir = config.out_path / 'manifests' / version / kb
        parsed_dir = config.out_path / 'parsed' / version / kb
        if manifests_dir.is_dir():
            pe_count = parse_extracted_files(manifests_dir, parsed_dir)
            print(f'  Parsed {pe_count} PE files')
        else:
            print(f'  WARNING: No manifests directory')

        update_file_hashes()

        # Step 3: Fetch VirusTotal data (optional, skips if proxy unavailable).
        vt_count = try_fetch_vt_data(parsed_dir)
        if vt_count > 0:
            print(f'  Fetched {vt_count} VT results')

        # Step 4: Group by filename (upd05).
        progress_state = {
            'update_kb': kb,
            'files_processed': [],
            'files_total': None,
        }
        upd05_group_by_filename(progress_state, None)
        print(f'  Grouped {progress_state["files_total"]} files')

        # Clean up extracted files to save disk.
        for d in ['manifests', 'parsed']:
            p = config.out_path / d
            if p.is_dir():
                shutil.rmtree(p, onerror=lambda f, path, e: (os.chmod(path, stat.S_IWRITE), f(path)))

        if updates_path.is_file():
            updates_path.unlink()

        # Mark KB as done.
        _mark_done(last_updates, all_updates, version, kb, last_path)

        batch_count += 1

        # Commit after each KB.
        ts = datetime.now().strftime('%Y-%m-%d %H:%M')
        commit_and_push(f'[{ts}] {version}: {kb} ({info["title"]})')

        print()

    print(f'\nProcessed {batch_count} KBs total')


def _mark_done(last_updates, all_updates, version, kb, last_path):
    """Mark a KB as processed in updates_last.json."""
    ver_dict = last_updates.setdefault(version, {})
    ver_dict[kb] = all_updates[version][kb]
    with open(last_path, 'w') as f:
        json.dump(last_updates, f, indent=4, sort_keys=True)


if __name__ == '__main__':
    main()
