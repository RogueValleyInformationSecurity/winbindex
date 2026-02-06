"""Compare CNMan/Issue#2 KB lists against updates_xp_2003.json to find missing KBs."""

import json
import re
from pathlib import Path

DATA_DIR = Path(r"C:\Users\jeff\Documents\winbindex\data")

# ---------- 1. Parse CNMan files for KB numbers and titles ----------

def parse_cnman_files():
    """Extract KB numbers and map them to titles from CNMan text files."""
    kb_numbers = set()
    kb_titles = {}  # kb_number (str of digits) -> list of titles

    for fname in ["cnman_wumt.txt", "cnman_chs.txt", "cnman_cht.txt"]:
        filepath = DATA_DIR / fname
        text = filepath.read_text(encoding="utf-8", errors="replace")

        # Extract all KB numbers from the entire text
        for m in re.finditer(r'(?i)\bKB(\d{6,7})\b', text):
            kb_numbers.add(m.group(1))

        # Try to associate KB numbers with section titles.
        lines = text.splitlines()
        current_title = None
        for line in lines:
            title_match = re.match(r'^\s*\[(.+?)\]\s*$', line)
            if title_match:
                current_title = title_match.group(1).strip()
            # Find KB numbers on this line
            for m in re.finditer(r'(?i)\bKB(\d{6,7})\b', line):
                kb_num = m.group(1)
                title = current_title if current_title else line.strip()
                if kb_num not in kb_titles:
                    kb_titles[kb_num] = []
                if title and title not in kb_titles[kb_num]:
                    kb_titles[kb_num].append(title)

    return kb_numbers, kb_titles


# ---------- 2. Issue #2 custom KBs ----------

ISSUE2_KBS = {
    "3197835", "4012583", "4012598", "4018271", "4018466",
    "4019204", "4022747", "4024323", "4024402", "4025218", "4500331"
}


# ---------- 3. Load existing updates_xp_2003.json ----------

def load_existing_kbs():
    """Load all KB numbers from updates_xp_2003.json across all OS variants."""
    json_path = DATA_DIR / "updates_xp_2003.json"
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = set()
    for os_key, kb_dict in data.items():
        for kb_key in kb_dict:
            # Keys are like "KB123456"
            m = re.match(r'(?i)KB(\d+)', kb_key)
            if m:
                existing.add(m.group(1))
    return existing, data


# ---------- 4. Classify missing KBs ----------

SKIP_PATTERNS = [
    (r'\.NET\s*Framework', '.NET Framework'),
    (r'Silverlight', 'Silverlight'),
    (r'Windows\s*Media\s*Player', 'Windows Media Player'),
    (r'Windows\s*Media\s*Format', 'Windows Media Format'),
    (r'Service\s*Pack', 'Service Pack'),
    (r'DirectX', 'DirectX'),
    (r'Visual\s*Basic', 'Visual Basic'),
    (r'CAPICOM', 'CAPICOM'),
    (r'Jscript\s*\d', 'JScript'),
    (r'Windows\s*Journal\s*Viewer', 'Windows Journal Viewer'),
    (r'MSXML', 'MSXML'),
    (r'Root\s*Certificate', 'Root Certificates'),
]


def classify_kb(kb_num, kb_titles):
    """Check if a KB's titles suggest it's a non-PE update."""
    titles = kb_titles.get(kb_num, [])
    flags = []
    for title in titles:
        for pattern, label in SKIP_PATTERNS:
            if re.search(pattern, title, re.IGNORECASE) and label not in flags:
                flags.append(label)
    return flags


# ---------- Main ----------

def main():
    cnman_kbs, kb_titles = parse_cnman_files()
    existing_kbs, existing_data = load_existing_kbs()

    # Combine CNMan + Issue #2
    all_wanted = cnman_kbs | ISSUE2_KBS

    print(f"CNMan KB count:          {len(cnman_kbs)}")
    print(f"Issue #2 KB count:       {len(ISSUE2_KBS)}")
    print(f"Combined unique KBs:     {len(all_wanted)}")
    print(f"Existing in JSON:        {len(existing_kbs)}")
    print()

    # Find overlap and missing
    overlap = all_wanted & existing_kbs
    missing = all_wanted - existing_kbs
    extra = existing_kbs - all_wanted  # in JSON but not in CNMan/Issue#2

    print(f"Already present:         {len(overlap)}")
    print(f"MISSING from JSON:       {len(missing)}")
    print(f"In JSON but not in list: {len(extra)}")
    print()

    # Sort missing
    missing_sorted = sorted(missing, key=lambda x: int(x))

    # Classify
    flagged = []
    clean = []
    for kb in missing_sorted:
        flags = classify_kb(kb, kb_titles)
        if flags:
            flagged.append((kb, flags, kb_titles.get(kb, [])))
        else:
            clean.append((kb, kb_titles.get(kb, [])))

    # Print clean (likely useful) missing KBs
    print("=" * 80)
    print(f"MISSING KBs - likely useful ({len(clean)}):")
    print("=" * 80)
    for kb, titles in clean:
        source = " [Issue#2]" if kb in ISSUE2_KBS else ""
        title_str = " | ".join(titles[:2]) if titles else "(no title found)"
        print(f"  KB{kb}{source}")
        print(f"    {title_str}")
    print()

    # Print flagged (possibly not useful) missing KBs
    print("=" * 80)
    print(f"MISSING KBs - flagged as possibly non-PE ({len(flagged)}):")
    print("=" * 80)
    for kb, flags, titles in flagged:
        source = " [Issue#2]" if kb in ISSUE2_KBS else ""
        title_str = " | ".join(titles[:2]) if titles else "(no title found)"
        flag_str = ", ".join(flags)
        print(f"  KB{kb}{source}  [{flag_str}]")
        print(f"    {title_str}")
    print()

    # Also show the "extra" KBs (in JSON but not in CNMan lists) - just counts by OS
    print("=" * 80)
    print(f"KBs in updates_xp_2003.json but NOT in CNMan/Issue#2 lists ({len(extra)}):")
    print("=" * 80)
    print("  (This is expected - CNMan lists are XP SP3 x86 only,")
    print("   but JSON also has XP-x64, 2003, 2003-x64 entries.)")
    # Count by OS variant
    for os_key in sorted(existing_data.keys()):
        os_kbs = set()
        for kb_key in existing_data[os_key]:
            m = re.match(r'(?i)KB(\d+)', kb_key)
            if m:
                os_kbs.add(m.group(1))
        os_extra = os_kbs - all_wanted
        os_overlap = os_kbs & all_wanted
        print(f"  {os_key}: {len(existing_data[os_key])} total KBs, "
              f"{len(os_overlap)} overlap with CNMan, "
              f"{len(os_extra)} unique to JSON")
    print()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"  Total missing KBs:       {len(missing)}")
    print(f"    Likely useful:         {len(clean)}")
    print(f"    Flagged (non-PE?):     {len(flagged)}")


if __name__ == "__main__":
    main()
