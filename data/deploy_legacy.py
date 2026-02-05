# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "isal",
#   "orjson",
#   "requests",
#   "signify",
# ]
# ///

from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import shutil
import json
import os
import re

# Swap config module so shared modules (upd05, symbol_server_link_enumerate)
# use legacy config transparently.
import config_legacy
import sys
sys.modules['config'] = config_legacy
config = config_legacy

from upd02_get_manifests_from_updates_legacy import main as upd02_get_manifests_from_updates_legacy
from upd03_parse_pe_files_legacy import main as upd03_parse_pe_files_legacy
from upd05_group_by_filename import main as upd05_group_by_filename
from symbol_server_link_enumerate import main as symbol_server_link_enumerate

deploy_start_time = datetime.now()


def filter_updates(updates, update_kbs):
    filtered = {}
    for windows_version in updates:
        for update_kb in updates[windows_version]:
            if update_kb in update_kbs:
                updates_dict = filtered.setdefault(windows_version, {})
                updates_dict[update_kb] = updates[windows_version][update_kb]

    return filtered


def prepare_updates():
    last_time_updates_path = config.out_path.joinpath('updates_last.json')
    if last_time_updates_path.is_file():
        with open(last_time_updates_path, 'r') as f:
            last_time_updates = json.load(f)
    else:
        last_time_updates = {}

    last_time_update_kbs = {update_kb for updates in last_time_updates.values() for update_kb in updates}

    # For legacy, we use the static curated list instead of scraping.
    source_updates_path = Path(__file__).parent.joinpath('updates_xp_2003.json')
    with open(source_updates_path, 'r') as f:
        uptodate_updates = json.load(f)

    # Write it as updates.json for the downstream pipeline stages.
    temp_updates_path = config.out_path.joinpath('updates.json')

    uptodate_update_kbs = set()
    for windows_version in uptodate_updates:
        for update_kb in uptodate_updates[windows_version]:
            # KBs can appear under multiple versions. Use (version, kb) for
            # uniqueness tracking, but update_kbs is just the KB set for
            # compatibility with the existing deploy pattern.
            uptodate_update_kbs.add(update_kb)

    def kb_sort_key(update_kb):
        for windows_version, updates in uptodate_updates.items():
            if update_kb in updates:
                update_info = updates[update_kb]
                return update_info['releaseDate'], update_info['releaseVersion'], update_kb
        assert False, update_kb

    new_update_kbs = sorted(uptodate_update_kbs - last_time_update_kbs, key=kb_sort_key)
    if len(new_update_kbs) == 0:
        print('No new updates')
        return None

    print(f'New updates: {new_update_kbs}')

    # Update one at a time.
    update_kb = new_update_kbs[0]

    print(f'Updating {update_kb}')

    single_update = filter_updates(uptodate_updates, {update_kb})

    with open(temp_updates_path, 'w') as f:
        json.dump(single_update, f, indent=4)

    with open(last_time_updates_path, 'w') as f:
        last_time_updates = filter_updates(uptodate_updates, last_time_update_kbs | {update_kb})
        json.dump(last_time_updates, f, indent=4, sort_keys=True)

    return update_kb


def add_update_to_info_progress_symbol_server(update_kb):
    info_progress_symbol_server_path = config.out_path.joinpath('info_progress_symbol_server.json')
    if info_progress_symbol_server_path.is_file():
        with open(info_progress_symbol_server_path, 'r') as f:
            info_progress_symbol_server = json.load(f)
    else:
        info_progress_symbol_server = {}

    updates = info_progress_symbol_server.get('updates')
    if updates is not None:
        assert update_kb not in updates, update_kb
        updates.append(update_kb)

    info_progress_symbol_server['next'] = None

    with open(info_progress_symbol_server_path, 'w') as f:
        json.dump(info_progress_symbol_server, f, indent=0, sort_keys=True)


def run_symbol_server_updates():
    # GitHub Actions has a 6 hour limit, so stop 10 minutes before that.
    time_to_stop = min(datetime.now() + timedelta(minutes=60), deploy_start_time + timedelta(hours=6, minutes=-10))
    if datetime.now() >= time_to_stop:
        return None

    print('Running symbol_server_link_enumerate')
    result = symbol_server_link_enumerate(time_to_stop)
    if result is None:
        return None

    num_files, too_many_retries = result

    return f'Updated info of {num_files} files from Microsoft Symbol Server'


def run_deploy():
    # GitHub Actions has a 6 hour limit, so stop 10 minutes before that.
    time_to_stop = deploy_start_time + timedelta(hours=6, minutes=-10)
    if datetime.now() >= time_to_stop:
        return None

    progress_file = config.out_path.joinpath('_progress.json')
    if progress_file.is_file():
        with open(progress_file, 'r') as f:
            progress_state = json.load(f)

        progress_file.unlink()
    else:
        new_single_update = prepare_updates()
        if not new_single_update:
            # No updates, try to fetch info instead.
            result = run_symbol_server_updates()
            if result:
                return result
            return None

        progress_state = {
            'update_kb': new_single_update,
            'files_processed': [],
            'files_total': None
        }

    print('Running upd02_get_manifests_from_updates_legacy')
    upd02_get_manifests_from_updates_legacy()

    print('Running upd03_parse_pe_files_legacy')
    upd03_parse_pe_files_legacy()

    if config.deploy_save_disk_space:
        clean_deploy_files(['manifests/'])

    print('Running upd05_group_by_filename')
    upd05_group_by_filename(progress_state, time_to_stop)

    if config.deploy_save_disk_space:
        clean_deploy_files(['parsed/'])

    if len(progress_state['files_processed']) < progress_state['files_total']:
        with open(progress_file, 'w') as f:
            json.dump(progress_state, f, indent=4)

        return f'Updated with files from {progress_state["update_kb"]} ({len(progress_state["files_processed"])} of {progress_state["files_total"]})'

    assert len(progress_state['files_processed']) == progress_state['files_total']

    config.out_path.joinpath('updates.json').unlink()

    add_update_to_info_progress_symbol_server(progress_state['update_kb'])

    return f'Updated with files from {progress_state["update_kb"]}'


def commit_deploy(pr_title):
    # Make sure no accidental changes in the main repo.
    # https://stackoverflow.com/a/25149786
    status = subprocess.check_output(['git', 'status', '--porcelain'], text=True)
    if status:
        raise Exception(f'Non-empty status:\n{status}')

    git_cmd = ['git', '-C', config.out_path]

    subprocess.check_call(git_cmd + ['add', '-A'])

    # https://stackoverflow.com/a/2659808
    result = subprocess.run(git_cmd + ['diff-index', '--quiet', '--cached', 'HEAD'])
    if result.returncode == 0:
        print('No changes to commit')
        return

    amend_last_commit = False
    if config.deploy_amend_last_commit:
        commit_count = int(subprocess.check_output(git_cmd + ['rev-list', '--count', 'HEAD'], text=True).rstrip('\n'))
        if commit_count > 1:
            amend_last_commit = True

    if amend_last_commit:
        last_commit_body = subprocess.check_output(git_cmd + ['log', '--format=%B', '-n1'], text=True)
        current_time_iso = datetime.now().isoformat(timespec='seconds').replace('T', ' ')
        new_body = f'[{current_time_iso}] {pr_title}\n\n{last_commit_body}'
        subprocess.check_call(git_cmd + ['commit', '--amend', '-m', new_body])
        subprocess.check_call(git_cmd + ['push', '--force-with-lease'])

        # Free disk space by removing old objects.
        subprocess.check_call(git_cmd + ['reflog', 'expire', '--expire=all', '--all'])
        subprocess.check_call(git_cmd + ['prune'])
    else:
        subprocess.check_call(git_cmd + ['commit', '-m', pr_title])
        subprocess.check_call(git_cmd + ['push'])


def clean_deploy_files(pathspecs=[]):
    git_cmd = ['git', '-C', config.out_path]

    cmd = git_cmd + ['clean', '-fdx']
    if pathspecs:
        cmd += ['--'] + pathspecs

    subprocess.check_call(cmd)


def main():
    # Unsupported in this flow.
    assert not config.extract_in_a_new_thread

    while True:
        pr_title = run_deploy()
        if not pr_title:
            print('run_deploy() returned None, exiting')
            return

        commit_deploy(pr_title)

        if config.deploy_save_disk_space:
            clean_deploy_files()


if __name__ == '__main__':
    main()
