# HTTP Proxy Scanner v1.4.0

A multi-threaded IPv4 HTTP proxy scanner with a Windows GUI (tkinter). Detects open HTTP proxies across large IP ranges with automatic verification against Baidu and Google, SQLite-backed proxy pool, and scan resume support.

## Features

- **O(1) target generation** — scans billions of IPs with zero memory overhead per target
- **CIDR & IP range input** — Start/End IP, CIDR notation, or quick-select presets (AWS, Azure, Aliyun, GCP)
- **62 common proxy ports** — pre-configured, or custom comma/hyphen port syntax
- **IP exclusion** — Private (RFC 1918), Loopback, Link-Local, Reserved/Multicast
- **Multi-threaded** — up to 2000 configurable scan threads
- **Proxy detection** — CONNECT tunnel + HTTP GET fallback, detects 407 auth proxies
- **Auto-verify on discovery** — background workers test each proxy against Baidu and Google
- **SQLite persistence** — verified proxies saved in `.proxies.db`, persistent across sessions
- **Proxy Pool** — view, re-verify, remove, and export verified proxies
- **Scan resume** — interrupted scans can be resumed from saved state
- **Three-tab notebook** — Results (verified proxies), Scan Log (real-time scan events), Proxy Pool
- **CSV export** — export verified proxies with verification status

## Requirements

- Python 3.10+
- No external dependencies (stdlib only: tkinter, socket, threading, sqlite3, etc.)

## Usage

```bash
python proxy_scanner.py
```

### Basic scan

1. Enter **Start IP** and **End IP** (or enter a CIDR and click Apply)
2. Enter **Ports** (comma-separated, ranges like `8000-8080`, or click a preset button)
3. Configure **Exclude IPs** checkboxes as needed
4. Set **Threads** (default 9) and **Timeout** (default 3s)
5. Click **Start**

### While scanning

- **Results** tab shows proxies as they are auto-verified (Global = Baidu+Google, China = Baidu only)
- **Scan Log** tab shows real-time scan events per target
- Status bar shows Scanned / Found / Auth / Verified / Excluded counts and speed

### Proxy Pool tab

- Displays all verified proxies from the SQLite database
- **Verify Selected** / **Verify All** — re-validate against Baidu and Google
- **Remove Selected** / **Remove All** — delete from display and database
- **Export Proxies** — CSV export with Pass/Fail verification status
- Auto-loads from database on tab switch, sorted newest-first

### Resume

- Click **Stop** during a scan to save state
- Reopen the app and click **Resume** to continue from where it left off
- Saved state files: `.scan_state.json`, `.proxies.json`

### Quick-select presets

| Button | IP Range |
|--------|----------|
| AWS (us-east) | `52.0.0.0/10` |
| Azure | `13.64.0.0/11` |
| Aliyun | `8.128.0.0/10` |
| GCP | `34.64.0.0/10` |

### Port presets

| Button | Content |
|--------|---------|
| Common Ports | 62 common proxy ports |
| HTTP/80 | Common HTTP ports |
| Squid | Default Squid ports |

## Architecture

```
"proxy_scanner.py" (1550+ lines, single file)
├── ProxyScanner       — scan engine (target gen, workers, verify workers)
│   ├── _worker()      — per-thread target probe (CONNECT + GET)
│   ├── _verify_worker() — background proxy verification (Baidu / Google)
│   └── ProxyDB        — SQLite persistence for verified proxies
└── App                — tkinter GUI
    ├── Scan Target    — IP/CIDR/port input
    ├── Exclude IPs    — exclusion toggles
    ├── Scan Control   — start/stop/resume/clear
    ├── Results tab    — verified proxy list
    ├── Scan Log tab   — real-time scan events
    └── Proxy Pool tab — DB-backed verified proxy management
```

## Database

- File: `.proxies.db` (SQLite WAL mode)
- Table `proxies`: `ip`, `port`, `ok`, `auth`, `conn_ms`, `type`, `baidu`, `google`, `tested`, `discovered`
- Only proxies passing Baidu or Google verification are saved
- Persistent across sessions; cleared only via the **Clear** button

## License

MIT
