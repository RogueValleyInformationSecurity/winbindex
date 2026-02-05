# Flow of scripts

![winbindex-scripts-flow.png](winbindex-scripts-flow.png)

## Text description

```
upd01_get_list_of_updates.py
 ├──> updates.json
 │     ├──> upd02_get_manifests_from_updates.py ──> manifests/
 │     └──> upd03_parse_manifests.py ──> parsed/
 └──> info_sources.json
       ├──> upd04_get_virustotal_data.py ──> virustotal/
       └──> (also read by upd01)

extract_data_from_iso_files.py ──> from_iso/

upd05_group_by_filename.py
 ├── reads: parsed/, virustotal/, from_iso/
 └── outputs: by_filename_compressed/, filenames.json
```

### Scripts

| Script | Inputs | Outputs |
|--------|--------|---------|
| `upd01_get_list_of_updates.py` | | `updates.json`, `info_sources.json` |
| `upd02_get_manifests_from_updates.py` | `updates.json` | `manifests/` |
| `upd03_parse_manifests.py` | `updates.json` | `parsed/` |
| `upd04_get_virustotal_data.py` | `info_sources.json` | `virustotal/` |
| `extract_data_from_iso_files.py` | | `from_iso/` |
| `upd05_group_by_filename.py` | `parsed/`, `virustotal/`, `from_iso/` | `by_filename_compressed/`, `filenames.json` |
