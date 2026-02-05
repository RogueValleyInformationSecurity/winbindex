# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests",
# ]
# ///
"""Discovers all available XP/2003 updates from the Microsoft Update Catalog
and writes updates_xp_2003.json.

Run with: uv run --script upd01_get_list_of_updates_legacy.py
"""

from pathlib import Path
import requests
import json
import time
import re

import config

# When run standalone, use legacy config.
if __name__ == '__main__':
    import sys
    import config_legacy
    sys.modules['config'] = config_legacy
    config = config_legacy


CATALOG_URL = 'https://www.catalog.update.microsoft.com/Search.aspx'

# Version classification patterns (same as upd02_legacy).
VERSION_PATTERNS = {
    'XP':       r'\bWindows XP\b(?!.*(?:x64|Professional x64))',
    'XP-x64':   r'\bWindows XP\b.*\b(?:x64|Professional x64)\b',
    '2003':     r'\bWindows Server 2003\b(?!.*(?:x64|R2))',
    '2003-x64': r'\bWindows Server 2003\b.*\bx64\b(?!.*\bR2\b)',
    '2003-R2':  r'\bWindows Server 2003 R2\b',
}

FILTER_REGEX = r'\bItanium\b|\bia64\b|\bIA-64\b'

# Multiple focused search queries to maximize coverage.
SEARCH_QUERIES = [
    'Security Update for Windows XP',
    'Update for Windows XP',
    'Critical Update for Windows XP',
    'Update Rollup for Windows XP',
    'Windows XP Service Pack',
    'Windows XP SP2',
    'Windows XP SP3',
    'Security Update for Windows Server 2003',
    'Update for Windows Server 2003',
    'Critical Update for Windows Server 2003',
    'Update Rollup for Windows Server 2003',
    'Windows Server 2003 Service Pack',
    'Windows Server 2003 SP2',
    'Windows Server 2003 R2',
]


def search_catalog_pages(session, query, max_pages=50):
    """Search the catalog with pagination via p= parameter."""
    title_p = r'onclick=\'goToDetails\("([a-f0-9\-]+)"\);\'[^>]*?>\s*(.*?)\s*</a>'
    all_entries = []

    for page in range(1, max_pages + 1):
        for attempt in range(3):
            try:
                resp = session.get(CATALOG_URL, params={'q': query, 'p': page}, timeout=30)
                if 'The website has encountered a problem' not in resp.text:
                    break
            except requests.RequestException:
                pass
            time.sleep(3)
        else:
            print(f'    Page {page}: failed after retries, stopping')
            break

        html = resp.text
        if 'We did not find any results' in html:
            break

        entries = re.findall(title_p, html)
        if not entries:
            break

        # Extract dates from the same row as each entry.
        # Table cells with dates are in MM/DD/YYYY format in td elements.
        # We find all rows and match entries to dates positionally.
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL)
        entry_dates = {}
        for row_html in rows:
            uid_match = re.search(
                r'onclick=\'goToDetails\("([a-f0-9\-]+)"\)',
                row_html
            )
            if uid_match:
                date_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4})', row_html)
                if date_match:
                    entry_dates[uid_match.group(1)] = date_match.group(1)

        for uid, title in entries:
            date_raw = entry_dates.get(uid, '')
            all_entries.append((uid, title, date_raw))

        time.sleep(0.3)

    return all_entries


def classify_title(title):
    """Return list of version IDs that match a title, filtering out Itanium."""
    if re.search(FILTER_REGEX, title, re.IGNORECASE):
        return []

    versions = []
    for version, pattern in VERSION_PATTERNS.items():
        if re.search(pattern, title, re.IGNORECASE):
            versions.append(version)

    return versions


def parse_date(date_raw):
    """Convert M/D/YYYY to YYYY-MM-DD."""
    if not date_raw:
        return ''
    parts = date_raw.split('/')
    if len(parts) == 3:
        return f'{parts[2]}-{int(parts[0]):02d}-{int(parts[1]):02d}'
    return ''


def main():
    session = requests.Session()

    # Collect all entries from all search queries.
    # Key by KB number; each KB maps to {versions, title, date, uid}.
    all_kbs = {}

    print('Discovering XP/2003 updates from Microsoft Update Catalog...\n')

    for query in SEARCH_QUERIES:
        print(f'Searching: "{query}"')
        entries = search_catalog_pages(session, query)

        new_count = 0
        for uid, title, date_raw in entries:
            # Extract KB number from title.
            m = re.search(r'\b(KB\d+)\b', title, re.IGNORECASE)
            if not m:
                continue

            kb = m.group(1).upper()
            versions = classify_title(title)
            if not versions:
                continue

            date_str = parse_date(date_raw)

            if kb not in all_kbs:
                all_kbs[kb] = {
                    'versions': set(),
                    'title': title,
                    'date': date_str,
                }
                new_count += 1

            entry = all_kbs[kb]
            entry['versions'].update(versions)

            # Prefer entries with dates.
            if date_str and not entry['date']:
                entry['date'] = date_str
                entry['title'] = title

        print(f'  Found {len(entries)} entries, {new_count} new unique KBs (total: {len(all_kbs)})')
        time.sleep(1)

    # Build output JSON grouped by version.
    output = {version: {} for version in config.LEGACY_VERSIONS}

    for kb, entry in all_kbs.items():
        for version in entry['versions']:
            if version in output:
                output[version][kb] = {
                    'releaseDate': entry['date'],
                    'releaseVersion': '',
                    'title': entry['title'],
                }

    # Sort each version's KBs by date then KB number.
    for version in output:
        sorted_kbs = sorted(
            output[version].items(),
            key=lambda x: (x[1]['releaseDate'] or '9999', x[0])
        )
        output[version] = dict(sorted_kbs)

    # Write output.
    output_path = Path(__file__).parent / 'updates_xp_2003.json'
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=4)

    # Summary.
    print()
    for version in output:
        print(f'  {version}: {len(output[version])} updates')

    total = sum(len(v) for v in output.values())
    print(f'\n  Total: {total} entries across {len(all_kbs)} unique KBs')
    print(f'  Written to {output_path}')


if __name__ == '__main__':
    main()
