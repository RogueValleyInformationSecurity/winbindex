from pathlib import Path

out_path_override = Path('.out_path_override')
out_path = Path(out_path_override.read_text().strip() if out_path_override.exists() else '.')
index_of_hashes_title = 'Winbindex Legacy Hashes'
index_of_hashes_out_path = out_path / '..' / 'hashes'

deploy_save_disk_space = True
deploy_amend_last_commit = True

windows_versions_unsupported = {}

updates_unsupported = set()

updates_alternative_links = {}

# Legacy pipeline handles multiple architectures per version, not a single global one.
updates_architecture = None
updates_never_removed = True
allow_missing_sha256_hash = True
allow_unknown_non_pe_files = True

verbose_run = False
verbose_progress = True
extract_in_a_new_thread = False
exit_on_first_error = True
high_mem_usage_for_performance = False
compression_level = 3
group_by_filename_processes = 4

# No delta processing for XP/2003.
delta_machine_type_values_supported = set()

delta_data_without_rift_table_names = set()
delta_data_without_rift_table_manifests = set()
delta_data_without_rift_table_hashes = set()

# Non-PE files (very rare).
file_hashes_non_pe = set()

tcb_launcher_descriptions = []
tcb_launcher_large_first_section_virtual_addresses = []

file_hashes_unusual_section_alignment = {}

file_names_zero_timestamp = set()
file_hashes_zero_timestamp = set()

file_hashes_small_non_signature_overlay = set()
file_hashes_unsigned_with_overlay = set()

file_details_unsigned_with_overlay = []

vt_proxy = 'socks5h://127.0.0.1:9150'  # Tor Browser SOCKS5
vt_skip_bulk_check = True  # Bulk endpoint blocks Tor exit nodes

def vt_on_rate_limit():
    """Request a new Tor circuit via the control port."""
    import socket
    from pathlib import Path
    cookie_path = Path.home() / 'Desktop' / 'Tor Browser' / 'Browser' / 'TorBrowser' / 'Data' / 'Tor' / 'control_auth_cookie'
    if not cookie_path.exists():
        return
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect(('127.0.0.1', 9151))
        s.send(f'AUTHENTICATE {cookie_path.read_bytes().hex()}\r\n'.encode())
        s.recv(1024)
        s.send(b'SIGNAL NEWNYM\r\n')
        s.recv(1024)
        s.close()
    except Exception:
        pass

file_hashes_mismatch = {}

# Legacy version identifiers.
LEGACY_VERSIONS = ['XP', 'XP-x64', '2003', '2003-x64']

# Search suffixes for the Microsoft Update Catalog, keyed by version ID.
CATALOG_SEARCH_SUFFIXES = {
    'XP':       'Windows XP',
    'XP-x64':   'Windows XP x64',
    '2003':     'Windows Server 2003',
    '2003-x64': 'Windows Server 2003 x64',
}
