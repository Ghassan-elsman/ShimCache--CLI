# Crow-Eye ShimCache Analyzer

**Version**: 1  
**Last Updated**: July 18, 2025  
**Author**: Ghassan elsman

## Description
Crow-Eye ShimCache Analyzer is a CLI tool for parsing Windows ShimCache data from the registry or offline SYSTEM hives. It extracts execution artifacts, supports Windows 7 and 10/11, and outputs to SQLite, JSON, or CSV. Features include UWP entry handling, sorting, and timestamp filtering.

## Installation
1. **Prerequisites**:
   - Python 3.6+ (e.g., `C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe`).
   - Windows for live registry analysis (admin privileges required).
   - SYSTEM hive file for offline analysis (e.g., `C:\Crow Eye\Artifacts Collectors\Target Artifacts\Registry Hives\SYSTEM`).

2. **Setup**:
   - Save `shicache_cli.py` to `C:\Shimcache CLI\shicache_cli.py`.
   - Set permissions:
     ```powershell
     icacls "C:\Shimcache CLI\shicache_cli.py" /grant Everyone:F
     ```
   - Run:
     ```powershell
     C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe "C:/Shimcache CLI/shicache_cli.py"
     ```
   - The script auto-installs dependencies (`tqdm`, `python-registry`) in a virtual environment (`C:\Shimcache CLI\venv_shimcache_analyzer`).

## Usage
### Interactive Mode
Run:
```powershell
C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe "C:/Shimcache CLI/shicache_cli.py" --sort-entries
```
**Menu Options**:
1. **Live Analysis**: Parse live registry (requires admin).
2. **Offline Analysis**: Parse SYSTEM hive (e.g., `C:\Crow Eye\Artifacts Collectors\Target Artifacts\Registry Hives\SYSTEM`).
3. **Select Output Format**: SQLite (default, `shimcache_data.db`), JSON, or CSV.
4. **Exit**.

### Command-Line Options
```bash
--sort-entries              Sort non-UWP entries by last_modified.
--enable-package-name       Include package_name for UWP entries.
--sort-uwp-by-position      Sort UWP entries by cache_entry_position.
--export-uwp                Export UWP entries to CSV/JSON.
--filter-old-timestamps     Filter timestamps before 2000-01-01.
--non-interactive           Run setup without interactive menu.
```

**Example**:
```powershell
C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe "C:/Shimcache CLI/shicache_cli.py" --sort-entries --enable-package-name --export-uwp
```

### Output
- **SQLite**: `C:\Shimcache CLI\shimcache_data.db`
  - `shimcache_entries`: Non-UWP entries.
  - `uwp_invalid_entries`: UWP entries.
- **JSON/CSV**: Optional output with `--export-uwp` for UWP entries.
- **Log**: `C:\Shimcache CLI\shimcache_analyzer.log`

**Verify**:
```powershell
sqlite3 "C:\Shimcache CLI\shimcache_data.db" "SELECT COUNT(*) FROM shimcache_entries;"
type "C:\Shimcache CLI\shimcache_analyzer.log" | findstr "Successfully read ShimCache"
```

## Troubleshooting
- **Database Error**:
  - Delete database:
    ```powershell
    del "C:\Shimcache CLI\shimcache_data.db"
    ```
  - Or enable `--enable-package-name`.
- **Missing Registry Key**:
  - Verify hive:
    ```powershell
    reg load HKLM\TempHive "C:\Crow Eye\Artifacts Collectors\Target Artifacts\Registry Hives\SYSTEM"
    reg query HKLM\TempHive\ControlSet001\Control\Session Manager\AppCompatCache
    reg unload HKLM\TempHive
    ```
- **Logs**:
  ```powershell
  type "C:\Shimcache CLI\shimcache_analyzer.log" | findstr "ERROR"
  ```
