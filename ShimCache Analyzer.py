
"""
Crow-Eye ShimCache Analyzer

A CLI-based tool for parsing Windows ShimCache (Application Compatibility Cache) data.
Extracts execution artifacts from the Windows registry or offline SYSTEM hive files and
supports multiple output formats for forensic analysis.

Author: Ghassan elsman
Version: 1
"""

import struct
import sqlite3
import datetime
import sys
import os
import json
import csv
import hashlib
import logging
import ctypes
import argparse
import subprocess
from pathlib import Path
from typing import List, Optional

LOGO = """
═══════════════════════════════════════════════════════════════════
 ██████╗██████╗  ██████╗ ██╗    ██╗      ███████╗██╗   ██╗███████╗
██╔════╝██╔══██╗██╔═══██╗██║    ██║      ██╔════╝╚██╗ ██╔╝██╔════╝
██║     ██████╔╝██║   ██║██║ █╗ ██║█████╗█████╗   ╚████╔╝ █████╗  
██║     ██╔══██╗██║   ██║██║███╗██║╚════╝██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝      ███████╗   ██║   ███████╗
 ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝       ╚══════╝   ╚═╝   ╚══════╝
                  [ CROW-EYE SHIMCACHE ANALYZER ]
═══════════════════════════════════════════════════════════════════
"""

try:
    from winreg import HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx, CloseKey
    LIVE_REGISTRY_AVAILABLE = True
except ImportError:
    LIVE_REGISTRY_AVAILABLE = False

def ensure_venv_and_relaunch():
    """
    Ensure virtual environment exists and relaunch script in it if not active.
    """
    logging.basicConfig(
        filename='shimcache_analyzer.log',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    script_dir = Path(__file__).parent.absolute()
    venv_path = script_dir / "venv_shimcache_analyzer"
    python_exe = sys.executable
    
    if os.environ.get('VIRTUAL_ENV') or sys.prefix != sys.base_prefix:
        print(f"✓ Running in virtual environment: {sys.prefix}")
        logging.debug(f"Script running in virtual environment: {sys.prefix}")
        return
    
    venv_path_str = os.path.normpath(str(venv_path))
    python_exe = os.path.normpath(python_exe)
    
    venv_python = os.path.normpath(os.path.join(venv_path_str, "Scripts" if os.name == 'nt' else "bin", "python.exe" if os.name == 'nt' else "python"))
    if not os.path.exists(venv_python):
        print(f"Creating virtual environment at {venv_path_str}...")
        logging.debug(f"Creating virtual environment at {venv_path_str}")
        try:
            subprocess.check_call([python_exe, "-m", "venv", venv_path_str])
            print(f"✓ Virtual environment created at {venv_path_str}")
            logging.debug(f"Virtual environment created at {venv_path_str}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create virtual environment: {e}")
            logging.error(f"Failed to create virtual environment: {e}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"❌ Python executable not found: {python_exe}")
            logging.error(f"Python executable not found: {python_exe}")
            sys.exit(1)
    
    print(f"Relaunching script in virtual environment: {venv_python}")
    logging.debug(f"Relaunching script in virtual environment: {venv_python}")
    try:
        new_env = os.environ.copy()
        new_env['VIRTUAL_ENV'] = venv_path_str
        new_env['PATH'] = os.path.join(venv_path_str, "Scripts" if os.name == 'nt' else "bin") + os.pathsep + new_env['PATH']
        cmd = [venv_python, os.path.normpath(sys.argv[0])] + sys.argv[1:]
        logging.debug(f"Relaunch command: {' '.join(cmd)}")
        os.execvpe(venv_python, cmd, new_env)
    except Exception as e:
        print(f"❌ Failed to relaunch in virtual environment: {e}")
        logging.error(f"Failed to relaunch in virtual environment: {e}")
        sys.exit(1)

def check_and_install_packages():
    """
    Check for required packages and install in virtual environment if missing.
    """
    required_packages = ['tqdm', 'python-registry']
    for package in required_packages:
        try:
            __import__(package)
            logging.debug(f"Package {package} already installed")
        except ImportError:
            print(f"Installing {package} in virtual environment...")
            logging.debug(f"Installing {package} in virtual environment")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✓ Successfully installed {package}")
                logging.debug(f"Successfully installed {package}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {package}: {e}")
                logging.error(f"Failed to install {package}: {e}")
                sys.exit(1)

ensure_venv_and_relaunch()
check_and_install_packages()
from tqdm import tqdm
from Registry import Registry

logging.basicConfig(
    filename='shimcache_analyzer.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def is_admin():
    """
    Check if the script is running with administrative privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class ShimCacheEntry:
    """
    Represents a single ShimCache entry with all relevant metadata.
    """
    def __init__(self):
        self.path = ""
        self.filename = ""
        self.package_name = "N/A"
        self.last_modified = None
        self.last_modified_readable = ""
        self.data_size = 0
        self.entry_size = 0
        self.cache_entry_position = 0
        self.entry_hash = ""
        self.is_uwp = False
    
    def generate_hash(self) -> str:
        """
        Generate MD5 hash of path and timestamp for duplicate detection.
        """
        hash_input = f"{self.path}_{self.last_modified or 'Unknown'}".encode('utf-8')
        return hashlib.md5(hash_input).hexdigest()
    
    def extract_filename(self):
        """
        Extract filename from full path and handle edge cases.
        """
        if self.path:
            try:
                self.filename = Path(self.path).name
            except Exception as e:
                logging.debug(f"Error extracting filename from path {self.path}: {e}")
                if '\\' in self.path:
                    self.filename = self.path.split('\\')[-1]
                elif '/' in self.path:
                    self.filename = self.path.split('/')[-1]
                else:
                    self.filename = self.path
        else:
            self.filename = "UNKNOWN"
    
    def extract_package_name(self):
        """
        Extract package name for UWP entries.
        """
        if self.is_uwp:
            parts = self.path.split('_')
            self.package_name = parts[0] if parts else "UNKNOWN"
        else:
            self.package_name = "N/A"
    
    def format_timestamp(self, filter_old_timestamps: bool = False):
        """
        Format timestamp to human-readable format, optionally filter old timestamps.
        """
        if self.last_modified:
            if filter_old_timestamps and self.last_modified.year < 2000:
                self.last_modified = None
                self.last_modified_readable = "Unknown"
            else:
                self.last_modified_readable = self.last_modified.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            self.last_modified_readable = "Unknown"

class ShimCacheParser:
    """
    Main parser class for ShimCache data extraction and analysis.
    """
    WINDOWS_10_SIGNATURE = 0x73743031
    WINDOWS_7_SIGNATURE_PATTERN = b'\x30\x00\x00\x00'
    
    def __init__(self, database_path: str = "shimcache_data.db", sort_entries: bool = False,
                 enable_package_name: bool = False, sort_uwp_by_position: bool = False,
                 export_uwp: bool = False, filter_old_timestamps: bool = False):
        """
        Initialize the ShimCache parser with optional features.
        """
        self.database_path = database_path
        self.sort_entries = sort_entries
        self.enable_package_name = enable_package_name
        self.sort_uwp_by_position = sort_uwp_by_position
        self.export_uwp = export_uwp
        self.filter_old_timestamps = filter_old_timestamps
        self.entries = []
        self.invalid_timestamp_count = 0
        self.uwp_count = 0
        self.uwp_invalid_count = 0
        self.failed_parses = 0
        self.analysis_time = datetime.datetime.now(tz=datetime.timezone.utc)
        self.setup_database()
    
    def setup_database(self):
        """
        Create SQLite database with tables for shimcache and UWP entries.
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        columns = ['filename TEXT NOT NULL', 'path TEXT NOT NULL', 'last_modified TEXT',
                   'last_modified_readable TEXT', 'data_size INTEGER DEFAULT 0',
                   'entry_size INTEGER DEFAULT 0', 'cache_entry_position INTEGER DEFAULT 0',
                   'entry_hash TEXT UNIQUE', 'is_uwp BOOLEAN DEFAULT FALSE',
                   'parsed_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP']
        if self.enable_package_name:
            columns.insert(2, 'package_name TEXT')
        
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS shimcache_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                {', '.join(columns)},
                UNIQUE(path, last_modified)
            )
        ''')
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS uwp_invalid_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                {', '.join(columns)},
                UNIQUE(path, last_modified_readable)
            )
        ''')
        
        cursor.execute("PRAGMA table_info(shimcache_entries)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        if self.enable_package_name and 'package_name' not in existing_columns:
            print("⚠️ Migrating shimcache_entries: Adding package_name column")
            logging.debug("Migrating shimcache_entries: Adding package_name column")
            try:
                cursor.execute("ALTER TABLE shimcache_entries ADD COLUMN package_name TEXT")
            except sqlite3.OperationalError as e:
                print(f"❌ Failed to migrate shimcache_entries: {e}")
                logging.error(f"Failed to migrate shimcache_entries: {e}")
                sys.exit(1)
        
        cursor.execute("PRAGMA table_info(uwp_invalid_entries)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        if self.enable_package_name and 'package_name' not in existing_columns:
            print("⚠️ Migrating uwp_invalid_entries: Adding package_name column")
            logging.debug("Migrating uwp_invalid_entries: Adding package_name column")
            try:
                cursor.execute("ALTER TABLE uwp_invalid_entries ADD COLUMN package_name TEXT")
            except sqlite3.OperationalError as e:
                print(f"❌ Failed to migrate uwp_invalid_entries: {e}")
                logging.error(f"Failed to migrate uwp_invalid_entries: {e}")
                sys.exit(1)
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_path ON shimcache_entries(path)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_filename ON shimcache_entries(filename)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_modified ON shimcache_entries(last_modified)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_entry_hash ON shimcache_entries(entry_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_uwp ON shimcache_entries(is_uwp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uwp_path ON uwp_invalid_entries(path)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uwp_filename ON uwp_invalid_entries(filename)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uwp_entry_hash ON uwp_invalid_entries(entry_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uwp_parsed_timestamp ON uwp_invalid_entries(parsed_timestamp)')
        if self.sort_uwp_by_position:
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_uwp_cache_entry_position ON uwp_invalid_entries(cache_entry_position)')
        
        conn.commit()
        conn.close()
        print(f"✓ Database initialized: {self.database_path}")
        logging.debug(f"Database initialized: {self.database_path}")
    
    def is_uwp_path(self, path: str) -> bool:
        """
        Check if a path corresponds to a UWP app.
        """
        uwp_indicators = [
            '8wekyb3d8bbwe', 'cw5n1h2txyewy', 'nzyj5cx40ttqa', 'zpdnekdrzrea0',
            'cv1g1gvanyjgm', 'e6fq5fg77me12', 'qbz5n2kfra8p0', '8j3eq9eme6ctt',
            'v826wp6bftszj', 'yxz26nhyzhsrt', 'b8gmsy6z3rxkj'
        ]
        return any(indicator in path.lower() for indicator in uwp_indicators)
    
    def filetime_to_datetime(self, filetime: int) -> Optional[datetime.datetime]:
        """
        Convert Windows FILETIME to Python datetime object.
        """
        try:
            if filetime == 0:
                self.invalid_timestamp_count += 1
                self.uwp_invalid_count += 1
                return None
            timestamp = filetime / 10000000.0 - 11644473600
            return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        except (ValueError, OSError) as e:
            self.invalid_timestamp_count += 1
            self.uwp_invalid_count += 1
            logging.debug(f"Invalid FILETIME value {filetime}: {e}")
            return None
    
    def detect_windows_version(self, data: bytes) -> str:
        """
        Detect Windows version based on ShimCache data patterns.
        """
        logging.debug(f"Detecting Windows version for data of length {len(data)} bytes")
        if len(data) < 52:
            logging.debug("Data too short for version detection")
            return "Unknown"
        for i in range(52, min(len(data) - 4, 200)):
            try:
                signature = struct.unpack('<I', data[i:i+4])[0]
                if signature == self.WINDOWS_10_SIGNATURE:
                    logging.debug(f"Windows 10/11 signature found at offset {i}")
                    return "Windows 10/11"
            except struct.error:
                continue
        if self.WINDOWS_7_SIGNATURE_PATTERN in data[:200]:
            logging.debug("Windows 7 signature pattern found")
            return "Windows 7"
        logging.debug("No known signature found")
        return "Unknown"
    
    def parse_windows_10_11(self, data: bytes) -> List[ShimCacheEntry]:
        """
        Parse Windows 10/11 ShimCache format.
        """
        entries = []
        index = 52
        parse_attempts = 0
        print("📊 Parsing Windows 10/11 format...")
        logging.debug("Parsing Windows 10/11 format")
        with tqdm(total=len(data)//100, desc="Parsing Entries", unit="entry") as pbar:
            while index < len(data) - 20:
                try:
                    if index + 4 > len(data):
                        logging.debug(f"Reached end of data at index {index}")
                        break
                    signature = struct.unpack('<I', data[index:index+4])[0]
                    if signature != self.WINDOWS_10_SIGNATURE:
                        index += 1
                        pbar.update(1)
                        continue
                    parse_attempts += 1
                    entry = ShimCacheEntry()
                    entry.cache_entry_position = index
                    index += 4
                    index += 4
                    if index + 4 > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: insufficient data for entry size at {index}")
                        break
                    entry.entry_size = struct.unpack('<I', data[index:index+4])[0]
                    index += 4
                    if index + 2 > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: insufficient data for path length at {index}")
                        break
                    path_length = struct.unpack('<H', data[index:index+2])[0]
                    index += 2
                    if index + path_length > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: path length {path_length} exceeds data at {index}")
                        break
                    try:
                        entry.path = data[index:index+path_length].decode('utf-16le', errors='ignore').rstrip('\x00')
                    except UnicodeDecodeError as e:
                        logging.debug(f"Unicode decode error at offset {index}: {e}")
                        entry.path = "DECODE_ERROR"
                    index += path_length
                    entry.extract_filename()
                    if self.enable_package_name:
                        entry.extract_package_name()
                    if index + 8 > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: insufficient data for filetime at {index}")
                        break
                    filetime = struct.unpack('<Q', data[index:index+8])[0]
                    entry.is_uwp = self.is_uwp_path(entry.path)
                    entry.last_modified = self.filetime_to_datetime(filetime)
                    entry.format_timestamp(self.filter_old_timestamps)
                    index += 8
                    if index + 2 > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: insufficient data for data size at {index}")
                        break
                    entry.data_size = struct.unpack('<H', data[index:index+2])[0]
                    index += 2
                    if index + entry.data_size > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: data size {entry.data_size} exceeds data at {index}")
                        break
                    index += entry.data_size
                    entry.entry_hash = entry.generate_hash()
                    if entry.is_uwp:
                        self.uwp_count += 1
                        self.save_to_uwp_invalid_table(entry)
                    else:
                        entries.append(entry)
                    pbar.update(1)
                except (struct.error, IndexError) as e:
                    logging.debug(f"Error parsing entry at offset {index}: {e}")
                    index += 1
                    pbar.update(1)
                    self.failed_parses += 1
                    parse_attempts += 1
                    continue
        if self.sort_entries:
            entries.sort(key=lambda x: x.last_modified or datetime.datetime.min, reverse=True)
        print(f"✓ Successfully parsed {len(entries)} non-UWP entries")
        logging.debug(f"Parsed {len(entries)} non-UWP entries, {self.failed_parses} failed parses, {parse_attempts} attempts")
        return entries
    
    def parse_windows_7(self, data: bytes) -> List[ShimCacheEntry]:
        """
        Parse Windows 7 ShimCache format.
        """
        entries = []
        print("📊 Parsing Windows 7 format...")
        logging.debug("Parsing Windows 7 format")
        try:
            if len(data) < 8:
                self.failed_parses += 1
                logging.debug(f"Failed parse: data too short ({len(data)} bytes)")
                return entries
            num_entries = struct.unpack('<I', data[4:8])[0]
            print(f"  📋 Found {num_entries} entries in Windows 7 format")
            logging.debug(f"Found {num_entries} entries in Windows 7 format")
            index = 8
            with tqdm(total=num_entries, desc="Parsing Entries", unit="entry") as pbar:
                for i in range(num_entries):
                    if index + 32 > len(data):
                        self.failed_parses += 1
                        logging.debug(f"Failed parse: insufficient data for entry {i} at {index}")
                        break
                    try:
                        entry = ShimCacheEntry()
                        entry.cache_entry_position = index
                        entry.entry_size = struct.unpack('<I', data[index:index+4])[0]
                        index += 4
                        index += 4
                        path_length = struct.unpack('<I', data[index:index+4])[0]
                        index += 4
                        path_offset = struct.unpack('<I', data[index:index+4])[0]
                        index += 4
                        filetime = struct.unpack('<Q', data[index:index+8])[0]
                        entry.is_uwp = self.is_uwp_path(entry.path)
                        entry.last_modified = self.filetime_to_datetime(filetime)
                        entry.format_timestamp(self.filter_old_timestamps)
                        index += 8
                        index += 8
                        entry.data_size = struct.unpack('<I', data[index:index+4])[0]
                        index += 4
                        index += 4
                        if path_offset < len(data) and path_offset + path_length <= len(data):
                            try:
                                entry.path = data[path_offset:path_offset+path_length].decode('utf-16le', errors='ignore').rstrip('\x00')
                            except UnicodeDecodeError as e:
                                logging.debug(f"Unicode decode error at offset {path_offset}: {e}")
                                entry.path = "DECODE_ERROR"
                        else:
                            entry.path = "INVALID_OFFSET"
                        entry.extract_filename()
                        if self.enable_package_name:
                            entry.extract_package_name()
                        entry.entry_hash = entry.generate_hash()
                        if entry.is_uwp:
                            self.uwp_count += 1
                            self.save_to_uwp_invalid_table(entry)
                        else:
                            entries.append(entry)
                        pbar.update(1)
                    except (struct.error, IndexError) as e:
                        logging.debug(f"Error parsing Windows 7 entry {i}: {e}")
                        pbar.update(1)
                        self.failed_parses += 1
                        continue
        except Exception as e:
            logging.error(f"Error parsing Windows 7 format: {e}")
            self.failed_parses += 1
        if self.sort_entries:
            entries.sort(key=lambda x: x.last_modified or datetime.datetime.min, reverse=True)
        print(f"✓ Successfully parsed {len(entries)} non-UWP entries")
        logging.debug(f"Parsed {len(entries)} non-UWP entries, {self.failed_parses} failed parses")
        return entries
    
    def save_to_uwp_invalid_table(self, entry: ShimCacheEntry):
        """
        Save UWP entry to uwp_invalid_entries table.
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        try:
            values = (
                entry.filename,
                entry.path,
                entry.last_modified.isoformat() if entry.last_modified else None,
                entry.last_modified_readable,
                entry.data_size,
                entry.entry_size,
                entry.cache_entry_position,
                entry.entry_hash,
                entry.is_uwp
            )
            if self.enable_package_name:
                values = (
                    entry.filename,
                    entry.path,
                    entry.package_name,
                    entry.last_modified.isoformat() if entry.last_modified else None,
                    entry.last_modified_readable,
                    entry.data_size,
                    entry.entry_size,
                    entry.cache_entry_position,
                    entry.entry_hash,
                    entry.is_uwp
                )
            placeholders = ','.join(['?' for _ in values])
            columns = 'filename, path, last_modified, last_modified_readable, data_size, entry_size, cache_entry_position, entry_hash, is_uwp'
            if self.enable_package_name:
                columns = 'filename, path, package_name, last_modified, last_modified_readable, data_size, entry_size, cache_entry_position, entry_hash, is_uwp'
            cursor.execute(f'''
                INSERT INTO uwp_invalid_entries ({columns})
                VALUES ({placeholders})
            ''', values)
            conn.commit()
            logging.debug(f"Saved UWP entry: {entry.path}")
        except sqlite3.OperationalError as e:
            print(f"❌ Database error saving UWP entry: {e}")
            logging.error(f"Database error saving UWP entry: {e}")
            sys.exit(1)
        except sqlite3.IntegrityError:
            logging.debug(f"Duplicate UWP entry skipped: {entry.path}")
        finally:
            conn.close()
    
    def save_uwp_to_csv(self, output_path: str):
        """
        Save UWP entries to CSV file.
        """
        headers = ['filename', 'path', 'last_modified', 'last_modified_readable', 'data_size',
                   'entry_size', 'cache_entry_position', 'entry_hash', 'is_uwp']
        if self.enable_package_name:
            headers.insert(2, 'package_name')
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            query = "SELECT " + ', '.join(headers) + " FROM uwp_invalid_entries"
            if self.sort_uwp_by_position:
                query += " ORDER BY cache_entry_position"
            cursor.execute(query)
            rows = cursor.fetchall()
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(zip(headers, row)))
            conn.close()
            print(f"✓ Saved {len(rows)} UWP entries to CSV: {output_path}")
            logging.debug(f"Saved {len(rows)} UWP entries to CSV: {output_path}")
        except Exception as e:
            print(f"❌ Failed to save UWP entries to CSV: {e}")
            logging.error(f"Failed to save UWP entries to CSV: {e}")
    
    def save_uwp_to_json(self, output_path: str):
        """
        Save UWP entries to JSON file.
        """
        headers = ['filename', 'path', 'last_modified', 'last_modified_readable', 'data_size',
                   'entry_size', 'cache_entry_position', 'entry_hash', 'is_uwp']
        if self.enable_package_name:
            headers.insert(2, 'package_name')
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            query = "SELECT " + ', '.join(headers) + " FROM uwp_invalid_entries"
            if self.sort_uwp_by_position:
                query += " ORDER BY cache_entry_position"
            cursor.execute(query)
            rows = cursor.fetchall()
            data = [dict(zip(headers, row)) for row in rows]
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            conn.close()
            print(f"✓ Saved {len(rows)} UWP entries to JSON: {output_path}")
            logging.debug(f"Saved {len(rows)} UWP entries to JSON: {output_path}")
        except Exception as e:
            print(f"❌ Failed to save UWP entries to JSON: {e}")
            logging.error(f"Failed to save UWP entries to JSON: {e}")
    
    def parse_shimcache_data(self, data: bytes) -> List[ShimCacheEntry]:
        """
        Main parsing function - detects version and parses accordingly.
        """
        if not data or len(data) < 20:
            print("❌ Invalid or empty ShimCache data")
            logging.error("Invalid or empty ShimCache data")
            self.failed_parses += 1
            return []
        version = self.detect_windows_version(data)
        print(f"🔍 Detected Windows version: {version}")
        logging.debug(f"Detected Windows version: {version}")
        if version == "Windows 10/11":
            return self.parse_windows_10_11(data)
        elif version == "Windows 7":
            return self.parse_windows_7(data)
        else:
            print("⚠️ Unknown Windows version, attempting Windows 10/11 parsing...")
            logging.warning("Unknown Windows version, attempting Windows 10/11 parsing")
            return self.parse_windows_10_11(data)
    
    def get_live_registry_data(self) -> Optional[bytes]:
        """
        Extract ShimCache data from live Windows registry.
        """
        if not LIVE_REGISTRY_AVAILABLE:
            print("❌ Live registry access not available on this platform")
            logging.error("Live registry access not available")
            return None
        try:
            registry_paths = [
                r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
                r"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache",
                r"SYSTEM\ControlSet002\Control\Session Manager\AppCompatCache"
            ]
            for path in registry_paths:
                try:
                    key = OpenKey(HKEY_LOCAL_MACHINE, path)
                    data, _ = QueryValueEx(key, "AppCompatCache")
                    CloseKey(key)
                    print(f"✓ Successfully read ShimCache data from {path}")
                    logging.debug(f"Read ShimCache data from {path}, length: {len(data)} bytes")
                    return data
                except FileNotFoundError:
                    logging.debug(f"Registry path not found: {path}")
                    continue
                except Exception as e:
                    logging.debug(f"Error reading registry path {path}: {e}")
                    continue
            print(f"❌ Could not find AppCompatCache in any control set (tried {', '.join(registry_paths)})")
            logging.error(f"Could not find AppCompatCache in any control set: {', '.join(registry_paths)}")
            return None
        except Exception as e:
            print(f"❌ Error accessing live registry: {e}")
            logging.error(f"Error accessing live registry: {e}")
            return None
    
    def get_offline_registry_data(self, hive_path: str) -> Optional[bytes]:
        """
        Extract ShimCache data from an offline SYSTEM registry hive file.
        """
        hive_path = os.path.normpath(hive_path)
        logging.debug(f"Attempting to read offline hive: {hive_path}")
        if not os.path.exists(hive_path):
            print(f"❌ Registry hive file not found: {hive_path}")
            print("   Please provide a valid path (e.g., C:\\Windows\\System32\\config\\SYSTEM or C:\\Crow Eye\\Artifacts Collectors\\Target Artifacts\\Registry Hives\\SYSTEM)")
            logging.error(f"Registry hive file not found: {hive_path}")
            return None
        if not os.path.isfile(hive_path):
            print(f"❌ Path is not a file: {hive_path}")
            print("   Please provide a valid SYSTEM registry hive file, not a directory")
            logging.error(f"Path is not a file: {hive_path}")
            return None
        try:
            with open(hive_path, 'rb') as f:
                header = f.read(4)
                if not header.startswith(b'regf'):
                    print(f"❌ Invalid registry hive file: {hive_path}")
                    print("   The file does not have a valid 'regf' header")
                    logging.error(f"Invalid registry hive file: {hive_path} (missing 'regf' header)")
                    return None
            reg = Registry.Registry(hive_path)
            registry_paths = [
                r"CurrentControlSet\Control\Session Manager\AppCompatCache",
                r"ControlSet001\Control\Session Manager\AppCompatCache",
                r"ControlSet002\Control\Session Manager\AppCompatCache"
            ]
            for path in registry_paths:
                try:
                    key = reg.open(path)
                    data = key.value("AppCompatCache").value()
                    print(f"✓ Successfully read ShimCache data from {path} in offline hive: {hive_path}")
                    logging.debug(f"Read ShimCache data from {path}, length: {len(data)} bytes")
                    return data
                except (Registry.RegistryKeyNotFoundException, Registry.RegistryValueNotFoundException):
                    logging.debug(f"Registry path not found in offline hive: {path}")
                    continue
            print(f"❌ Could not find AppCompatCache in any control set (tried {', '.join(registry_paths)})")
            print(f"   Ensure the file is a valid SYSTEM registry hive with the AppCompatCache key")
            logging.error(f"Could not find AppCompatCache in any control set: {', '.join(registry_paths)}")
            return None
        except Exception as e:
            print(f"❌ Error reading offline registry hive {hive_path}: {e}")
            print("   The file may be corrupted or not a valid SYSTEM registry hive")
            logging.error(f"Error reading offline registry hive {hive_path}: {e}")
            return None
    
    def check_duplicate_exists(self, entry: ShimCacheEntry, table: str = "shimcache_entries") -> bool:
        """
        Check if an entry already exists in the specified table.
        """
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE entry_hash = ?", (entry.entry_hash,))
            count = cursor.fetchone()[0]
            return count > 0
        except sqlite3.OperationalError as e:
            logging.error(f"Error checking duplicates in {table}: {e}")
            return False
        finally:
            conn.close()
    
    def save_to_database(self, entries: List[ShimCacheEntry]):
        """
        Save non-UWP entries to shimcache_entries table.
        """
        if not entries:
            print("📝 No non-UWP entries to save")
            logging.debug("No non-UWP entries to save")
            return 0, 0
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        new_entries = 0
        duplicates = 0
        try:
            for entry in entries:
                if self.check_duplicate_exists(entry, "shimcache_entries"):
                    duplicates += 1
                    continue
                values = (
                    entry.filename,
                    entry.path,
                    entry.last_modified.isoformat() if entry.last_modified else None,
                    entry.last_modified_readable,
                    entry.data_size,
                    entry.entry_size,
                    entry.cache_entry_position,
                    entry.entry_hash,
                    entry.is_uwp
                )
                if self.enable_package_name:
                    values = (
                        entry.filename,
                        entry.path,
                        entry.package_name,
                        entry.last_modified.isoformat() if entry.last_modified else None,
                        entry.last_modified_readable,
                        entry.data_size,
                        entry.entry_size,
                        entry.cache_entry_position,
                        entry.entry_hash,
                        entry.is_uwp
                    )
                placeholders = ','.join(['?' for _ in values])
                columns = 'filename, path, last_modified, last_modified_readable, data_size, entry_size, cache_entry_position, entry_hash, is_uwp'
                if self.enable_package_name:
                    columns = 'filename, path, package_name, last_modified, last_modified_readable, data_size, entry_size, cache_entry_position, entry_hash, is_uwp'
                cursor.execute(f'''
                    INSERT INTO shimcache_entries ({columns})
                    VALUES ({placeholders})
                ''', values)
                new_entries += 1
            conn.commit()
            print(f"✓ Database update complete: {new_entries} new, {duplicates} duplicates skipped")
            logging.debug(f"Saved {new_entries} new entries, skipped {duplicates} duplicates")
        except sqlite3.OperationalError as e:
            print(f"❌ Database error saving entries: {e}")
            logging.error(f"Database error saving entries: {e}")
            sys.exit(1)
        finally:
            conn.close()
        return new_entries, duplicates
    
    def save_to_json(self, entries: List[ShimCacheEntry], output_path: str):
        """
        Save non-UWP entries to JSON file.
        """
        data = [{
            'filename': entry.filename,
            'path': entry.path,
            'package_name': entry.package_name if self.enable_package_name else None,
            'last_modified': entry.last_modified.isoformat() if entry.last_modified else None,
            'last_modified_readable': entry.last_modified_readable,
            'data_size': entry.data_size,
            'entry_size': entry.entry_size,
            'cache_entry_position': entry.cache_entry_position,
            'entry_hash': entry.entry_hash,
            'is_uwp': entry.is_uwp
        } for entry in entries]
        try:
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✓ Saved {len(entries)} non-UWP entries to JSON: {output_path}")
            logging.debug(f"Saved {len(entries)} non-UWP entries to JSON: {output_path}")
        except Exception as e:
            print(f"❌ Failed to save JSON: {e}")
            logging.error(f"Failed to save JSON to {output_path}: {e}")
    
    def save_to_csv(self, entries: List[ShimCacheEntry], output_path: str):
        """
        Save non-UWP entries to CSV file.
        """
        headers = ['filename', 'path', 'last_modified', 'last_modified_readable', 'data_size',
                   'entry_size', 'cache_entry_position', 'entry_hash', 'is_uwp']
        if self.enable_package_name:
            headers.insert(2, 'package_name')
        try:
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for entry in entries:
                    row = {
                        'filename': entry.filename,
                        'path': entry.path,
                        'last_modified': entry.last_modified.isoformat() if entry.last_modified else None,
                        'last_modified_readable': entry.last_modified_readable,
                        'data_size': entry.data_size,
                        'entry_size': entry.entry_size,
                        'cache_entry_position': entry.cache_entry_position,
                        'entry_hash': entry.entry_hash,
                        'is_uwp': entry.is_uwp
                    }
                    if self.enable_package_name:
                        row['package_name'] = entry.package_name
                    writer.writerow(row)
            print(f"✓ Saved {len(entries)} non-UWP entries to CSV: {output_path}")
            logging.debug(f"Saved {len(entries)} non-UWP entries to CSV: {output_path}")
        except Exception as e:
            print(f"❌ Failed to save CSV: {e}")
            logging.error(f"Failed to save CSV to {output_path}: {e}")
    
    def print_summary(self, entries: List[ShimCacheEntry]):
        """
        Print comprehensive summary statistics.
        """
        if not entries and self.uwp_count == 0:
            print("📊 No entries found")
            logging.debug("No entries found")
            return
        total = len(entries) + self.uwp_count
        non_uwp_valid = len([e for e in entries if e.last_modified])
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM uwp_invalid_entries WHERE last_modified IS NOT NULL")
            uwp_valid = cursor.fetchone()[0]
        except sqlite3.OperationalError as e:
            print(f"❌ Error querying uwp_invalid_entries: {e}")
            logging.error(f"Error querying uwp_invalid_entries: {e}")
            uwp_valid = 0
        finally:
            conn.close()
        
        valid_timestamps = non_uwp_valid + uwp_valid
        valid_timestamp_percentage = (valid_timestamps / total * 100) if total > 0 else 0
        successful_parses = len(entries) + self.uwp_count
        total_attempts = successful_parses + self.failed_parses
        parse_success_percentage = (successful_parses / total_attempts * 100) if total_attempts > 0 else 0
        
        extensions = {}
        for entry in entries:
            if '.' in entry.filename:
                parts = entry.filename.split('.')
                if len(parts) >= 2:
                    ext = parts[-1].lower()
                    if ext.isalnum() and len(ext) <= 10:
                        extensions[ext] = extensions.get(ext, 0) + 1
        timestamps = [e.last_modified for e in entries if e.last_modified]
        
        print(f"\n🎯 === ShimCache Analysis Summary ===")
        print(f"📊 Total entries parsed: {total}")
        print(f"📱 UWP entries (saved to uwp_invalid_entries): {self.uwp_count} ({self.uwp_invalid_count} with Unknown timestamps)")
        print(f"📌 Non-UWP entries (saved to shimcache_entries): {len(entries)}")
        print(f"📊 Percentage of Successfully Parsed Entries: {parse_success_percentage:.2f}% ({successful_parses}/{total_attempts} attempts)")
        print(f"📈 Valid Timestamps: {valid_timestamps} ({non_uwp_valid} non-UWP, {uwp_valid} UWP)")
        print(f"📈 Percentage of Entries with Valid/Estimated Timestamps: {valid_timestamp_percentage:.2f}%")
        print(f"💾 Database: {self.database_path}")
        if self.sort_entries:
            print("🔧 Non-UWP entries sorted by last_modified (descending)")
        if self.sort_uwp_by_position:
            print("🔧 UWP entries sorted by cache_entry_position in database")
        if self.filter_old_timestamps:
            print("🔧 Timestamps before 2000-01-01 filtered as Unknown")
        if timestamps:
            oldest = min(timestamps)
            newest = max(timestamps)
            print(f"📅 Non-UWP time range: {oldest.strftime('%Y-%m-%d')} to {newest.strftime('%Y-%m-%d')}")
        print(f"\n🔧 Top file extensions (non-UWP):")
        for ext, count in sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  .{ext}: {count} files")
        logging.debug(f"Summary: Total={total}, UWP={self.uwp_count}, Invalid UWP={self.uwp_invalid_count}, Non-UWP={len(entries)}, Valid timestamps={valid_timestamps}, Parse success={parse_success_percentage:.2f}%")
    
    def process_shimcache_data(self, data: bytes, output_format: str, output_path: str):
        """
        Process ShimCache data and save to specified format.
        """
        if data is None:
            print("❌ No ShimCache data to process")
            logging.error("No ShimCache data to process")
            return
        entries = self.parse_shimcache_data(data)
        if not entries and self.uwp_count == 0:
            print("❌ No entries were successfully parsed")
            logging.error("No entries were successfully parsed")
            return
        print("🔄 Processing entries...")
        logging.debug("Processing entries")
        for entry in tqdm(entries, desc="Processing Entries"):
            entry.extract_filename()
            if self.enable_package_name:
                entry.extract_package_name()
            entry.format_timestamp(self.filter_old_timestamps)
        if output_format.lower() == 'json':
            self.save_to_json(entries, output_path)
            if self.export_uwp:
                self.save_uwp_to_json(output_path.replace('.json', '_uwp.json'))
        elif output_format.lower() == 'csv':
            self.save_to_csv(entries, output_path)
            if self.export_uwp:
                self.save_uwp_to_csv(output_path.replace('.csv', '_uwp.csv'))
        else:
            self.save_to_database(entries)
            if self.export_uwp:
                self.save_uwp_to_csv('uwp_invalid_entries.csv')
                self.save_uwp_to_json('uwp_invalid_entries.json')
        self.print_summary(entries)
        print(f"\n✅ Analysis complete! Check output: {output_path if output_format.lower() in ['json', 'csv'] else self.database_path}")
        logging.debug(f"Analysis complete: Output to {output_path if output_format.lower() in ['json', 'csv'] else self.database_path}")

def display_menu():
    """
    Display the CLI menu without logo.
    """
    print("\n=== CROW-EYE SHIMCACHE ANALYZER MENU ===")
    print("1. Live Analysis (Registry)")
    print("2. Offline Analysis (SYSTEM Hive)")
    print("3. Select Output Format")
    print("4. Exit")

def select_output_format(current_format: str, current_path: str) -> tuple[str, str]:
    """
    Allow user to select output format and file path.
    """
    print(f"\nCurrent output format: {current_format.upper()} ({current_path})")
    print("Available formats: 1. SQLITE, 2. JSON, 3. CSV")
    choice = input("Enter format number (1-3) or press Enter to keep current: ")
    if choice == '1':
        output_format = 'sqlite'
        default_path = 'shimcache_data.db'
    elif choice == '2':
        output_format = 'json'
        default_path = 'shimcache_data.json'
    elif choice == '3':
        output_format = 'csv'
        default_path = 'shimcache_data.csv'
    else:
        return current_format, current_path
    output_path = input(f"Enter output path (default: {default_path}): ") or default_path
    logging.debug(f"Selected output format: {output_format}, path: {output_path}")
    return output_format, output_path

def clear_console():
    """
    Clear the console with error handling.
    """
    try:
        if os.name == 'nt':
            subprocess.run('cls', shell=True, check=True, capture_output=True)
        else:
            subprocess.run('clear', shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to clear console: {e}")
        logging.warning(f"Failed to clear console: {e}")
    except Exception as e:
        print(f"⚠️ Error clearing console: {e}")
        logging.warning(f"Error clearing console: {e}")

def main():
    """
    Main function with CLI interface.
    """
    parser = argparse.ArgumentParser(description="Crow-Eye ShimCache Analyzer")
    parser.add_argument('--sort-entries', action='store_true', help="Sort non-UWP entries by last_modified")
    parser.add_argument('--non-interactive', action='store_true', help="Run in non-interactive mode")
    parser.add_argument('--enable-package-name', action='store_true', help="Enable package_name for UWP entries")
    parser.add_argument('--sort-uwp-by-position', action='store_true', help="Sort UWP entries by cache_entry_position")
    parser.add_argument('--export-uwp', action='store_true', help="Export UWP entries to CSV/JSON")
    parser.add_argument('--filter-old-timestamps', action='store_true', help="Filter timestamps before 2000-01-01")
    args = parser.parse_args()

    clear_console()
    print(LOGO)
    logging.debug("Crow-Eye ShimCache Analyzer started")
    
    output_format = 'sqlite'
    output_path = 'shimcache_data.db'
    parser = ShimCacheParser(
        output_path,
        sort_entries=args.sort_entries,
        enable_package_name=args.enable_package_name,
        sort_uwp_by_position=args.sort_uwp_by_position,
        export_uwp=args.export_uwp,
        filter_old_timestamps=args.filter_old_timestamps
    )
    
    if args.non_interactive:
        print("Running in non-interactive mode. Virtual environment setup complete.")
        logging.debug("Running in non-interactive mode")
        sys.exit(0)

    while True:
        display_menu()
        print(f"\nCurrent output format: {output_format.upper()} ({output_path})")
        if args.sort_entries:
            print("Non-UWP entries sorted by last_modified (descending)")
        if args.enable_package_name:
            print("Package name enabled for UWP entries")
        if args.sort_uwp_by_position:
            print("UWP entries sorted by cache_entry_position")
        if args.export_uwp:
            print("UWP entries will be exported to CSV/JSON")
        if args.filter_old_timestamps:
            print("Timestamps before 2000-01-01 filtered as Unknown")
        choice = input("Enter a number (1-4) to select an option: ")
        logging.debug(f"User selected menu option: {choice}")
        if choice == '1':
            if not is_admin():
                print("❌ This script requires administrative privileges for live registry access.")
                print("   Run as administrator or select option 2 for offline analysis.")
                logging.warning("Live analysis attempted without admin privileges")
                continue
            print("Performing live analysis on registry...")
            logging.debug("Performing live analysis on registry")
            data = parser.get_live_registry_data()
            parser.process_shimcache_data(data, output_format, output_path)
        elif choice == '2':
            max_attempts = 3
            attempts = 0
            while attempts < max_attempts:
                hive_path = input("Enter path to SYSTEM registry hive file (e.g., C:\\Windows\\System32\\config\\SYSTEM): ")
                logging.debug(f"Offline analysis requested for hive: {hive_path}")
                if not hive_path.strip():
                    print("❌ No hive path provided. Please enter a valid path.")
                    logging.error("No hive path provided")
                    attempts += 1
                    if attempts < max_attempts:
                        print(f"   {max_attempts - attempts} attempts remaining.")
                    continue
                data = parser.get_offline_registry_data(hive_path)
                if data is not None:
                    print(f"📊 Retrieved {len(data):,} bytes of ShimCache data")
                    parser.process_shimcache_data(data, output_format, output_path)
                    break
                attempts += 1
                if attempts < max_attempts:
                    print(f"   {max_attempts - attempts} attempts remaining.")
            else:
                print(f"❌ Failed to access valid SYSTEM hive after {max_attempts} attempts.")
                logging.error(f"Failed to access valid SYSTEM hive after {max_attempts} attempts")
        elif choice == '3':
            output_format, output_path = select_output_format(output_format, output_path)
            if output_format == 'sqlite' and output_path != parser.database_path:
                parser.database_path = output_path
                parser.setup_database()
        elif choice == '4':
            print("Exiting Crow-Eye ShimCache Analyzer...")
            logging.debug("Exiting Crow-Eye ShimCache Analyzer")
            sys.exit(0)
        else:
            print("❌ Invalid choice. Please enter a number between 1 and 4.")
            logging.warning(f"Invalid menu choice: {choice}")

if __name__ == "__main__":
    main()
