#!/usr/bin/env python3
"""
HTTP Proxy Scanner v1.4.0
Multi-threaded IPv4 HTTP proxy scanner with Windows GUI.
Supports CIDR, IP exclusion, proxy pool verification, scan resume,
auto-verify on discovery, SQLite persistence.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import socket
import ipaddress
import time
from datetime import datetime
import csv
import os
import json
import sqlite3
from collections import deque

__version__ = "1.4.0"

DEFAULT_PORTS = [80, 81, 88, 443, 808, 888, 1080, 1081, 2080, 3000,
                 3127, 3128, 3129, 4444, 5000, 5001, 6588, 7000, 7001,
                 7070, 7777, 8000, 8001, 8080, 8081, 8082, 8088, 8090,
                 8118, 8123, 8181, 8282, 8300, 8443, 8444, 8500, 8580,
                 8600, 8800, 8880, 8888, 8889, 8989, 9000, 9050, 9080,
                 9090, 9150, 9292, 9443, 9500, 9800, 9898, 9998, 9999,
                 10000, 10001, 10010, 10801, 18080, 20000, 31280]

MAX_RESULTS_ALL = 100_000
MAX_LOG_LINES = 1000
MAX_TREE_ITEMS = 10_000

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          ".scan_state.json")
PROXIES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".proxies.json")

EXCLUDE_PRESETS = {
    "private":   [("10.0.0.0", "10.255.255.255"),
                  ("172.16.0.0", "172.31.255.255"),
                  ("192.168.0.0", "192.168.255.255")],
    "loopback":  [("127.0.0.0", "127.255.255.255")],
    "linklocal": [("169.254.0.0", "169.254.255.255")],
    "reserved":  [("0.0.0.0", "0.255.255.255"),
                  ("224.0.0.0", "239.255.255.255"),
                  ("240.0.0.0", "255.255.255.255")],
}


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       ".proxies.db")


class ProxyDB:
    """SQLite-backed proxy persistence."""

    def __init__(self):
        self._lock = threading.Lock()
        self._conn = None
        self._save_count = 0
        self._init()

    def _conn_(self):
        if self._conn is None:
            self._conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _init(self):
        with self._lock:
            c = self._conn_()
            c.execute("""
                CREATE TABLE IF NOT EXISTS proxies (
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    ok INTEGER DEFAULT 0,
                    auth INTEGER DEFAULT 0,
                    conn_ms REAL DEFAULT 0,
                    type TEXT DEFAULT '',
                    baidu INTEGER DEFAULT 0,
                    google INTEGER DEFAULT 0,
                    tested TEXT DEFAULT '',
                    discovered TEXT DEFAULT '',
                    PRIMARY KEY (ip, port)
                )
            """)
            c.commit()

    def save(self, proxy):
        with self._lock:
            self._conn_().execute("""
                INSERT OR REPLACE INTO proxies
                (ip, port, ok, auth, conn_ms, type, baidu, google, tested, discovered)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                proxy["ip"], proxy["port"],
                1 if proxy.get("ok") else 0,
                1 if proxy.get("auth") else 0,
                proxy.get("conn_ms", 0),
                proxy.get("type", ""),
                1 if proxy.get("baidu") else 0,
                1 if proxy.get("google") else 0,
                proxy.get("tested", proxy.get("time", "")),
                proxy.get("time", ""),
            ))
            self._conn_().commit()
            self._save_count += 1

    def save_many(self, proxies):
        with self._lock:
            for p in proxies:
                self._conn_().execute("""
                    INSERT OR REPLACE INTO proxies
                    (ip, port, ok, auth, conn_ms, type, baidu, google, tested, discovered)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (
                    p["ip"], p["port"],
                    1 if p.get("ok") else 0,
                    1 if p.get("auth") else 0,
                    p.get("conn_ms", 0),
                    p.get("type", ""),
                    1 if p.get("baidu") else 0,
                    1 if p.get("google") else 0,
                    p.get("tested", p.get("time", "")),
                    p.get("time", ""),
                ))
            self._conn_().commit()
            self._save_count += len(proxies)

    def load_all(self):
        with self._lock:
            rows = self._conn_().execute(
                "SELECT ip,port,ok,auth,conn_ms,type,baidu,google,tested,discovered "
                "FROM proxies ORDER BY discovered DESC"
            ).fetchall()
        return [
            {
                "ip": r[0], "port": r[1],
                "ok": bool(r[2]), "auth": bool(r[3]),
                "conn_ms": r[4], "type": r[5],
                "baidu": bool(r[6]), "google": bool(r[7]),
                "tested": r[8] or "", "time": r[9] or "",
            }
            for r in rows
        ]

    def count_verified(self):
        with self._lock:
            row = self._conn_().execute(
                "SELECT COUNT(*) FROM proxies WHERE baidu=1 OR google=1 OR auth=1"
            ).fetchone()
            return row[0] if row else 0

    def delete(self, ip, port):
        with self._lock:
            self._conn_().execute(
                "DELETE FROM proxies WHERE ip=? AND port=?", (ip, port))
            self._conn_().commit()

    def clear(self):
        with self._lock:
            self._conn_().execute("DELETE FROM proxies")
            self._conn_().commit()

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


def parse_ports(s):
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                lo, hi = int(a.strip()), int(b.strip())
                if lo > hi:
                    lo, hi = hi, lo
                ports.update(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return sorted(p for p in ports if 1 <= p <= 65535)


# ====================================================================
# Scanner engine
# ====================================================================

class ProxyScanner:
    def __init__(self):
        self._running = False
        self._workers = []
        self._next_index = 0
        self._total = 0
        self._start_int = 0
        self._end_int = 0
        self._ports = []
        self._index_lock = threading.Lock()
        self._last_save = 0
        self._save_interval = 500

        self._exclude_ranges = []
        self._exclude_count = 0

        self._speed_log = []

        self.stats = {"scanned": 0, "found": 0, "auth": 0, "failed": 0,
                      "total": 0, "start_time": 0}
        self._stats_lock = threading.Lock()

        # result buffers
        self._all = []
        self._all_lock = threading.Lock()
        self._proxies = []       # extended: {ip,port,ok,auth,time,conn_ms,baidu,google,type}
        self._proxies_lock = threading.Lock()
        self._new = []
        self._new_lock = threading.Lock()

        # scan log (last 1000 entries for Log tab)
        self._scan_log = deque(maxlen=MAX_LOG_LINES)
        self._scan_log_lock = threading.Lock()

        self._max_results = MAX_RESULTS_ALL
        self._verified_new = deque()

        # auto-verify
        self._verify_queue = queue.Queue()
        self._verify_workers = []
        self._verify_running = False
        self.db = ProxyDB()

    # ---- target generation ----

    def _is_excluded(self, ip_int):
        for s, e in self._exclude_ranges:
            if s <= ip_int <= e:
                return True
        return False

    def _next_target(self):
        while True:
            with self._index_lock:
                idx = self._next_index
                self._next_index += 1
            if idx >= self._total:
                return None
            p = len(self._ports)
            ip_int = self._start_int + idx // p
            if ip_int > self._end_int:
                return None
            if self._is_excluded(ip_int):
                nxt = ((idx // p) + 1) * p
                with self._index_lock:
                    if self._next_index < nxt:
                        self._next_index = nxt
                continue
            return (str(ipaddress.IPv4Address(ip_int)), self._ports[idx % p])

    # ---- proxy detection ----

    @staticmethod
    def _recv(sock):
        resp = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    break
            except socket.timeout:
                break
        return resp

    def _check(self, host, port, timeout):
        """
        Returns (proxy_type, conn_ms).
        proxy_type: 'ok' | 'auth' | 'no' | 'error'
        """
        for method in ["CONNECT", "GET"]:
            try:
                t0 = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((host, port))
                    conn_ms = (time.time() - t0) * 1000

                    if method == "CONNECT":
                        req = (f"CONNECT www.example.com:80 HTTP/1.1\r\n"
                               f"Host: www.example.com:80\r\n"
                               f"User-Agent: Mozilla/5.0\r\n"
                               f"Connection: close\r\n\r\n")
                    else:
                        req = (f"GET http://www.example.com/ HTTP/1.1\r\n"
                               f"Host: www.example.com\r\n"
                               f"User-Agent: Mozilla/5.0\r\n"
                               f"Connection: close\r\n\r\n")

                    s.sendall(req.encode())
                    resp = self._recv(s)

                if resp:
                    line = resp.split(b"\r\n", 1)[0].decode(errors="ignore")
                    if "200" in line:
                        return ("ok", conn_ms)
                    if "407" in line:
                        return ("auth", conn_ms)
                    if method == "GET" and "HTTP/" in line:
                        return ("ok", conn_ms)
            except socket.timeout:
                if method == "CONNECT":
                    continue
                return ("error", 0)
            except OSError as e:
                if method == "CONNECT":
                    continue
                return ("error", 0)
        return ("no", 0)

    # ---- proxy verification (Baidu / Google) ----

    @staticmethod
    def _tunnel_get(proxy_ip, proxy_port, target_host, target_port, path, timeout):
        """Open a CONNECT tunnel through proxy and GET a page."""
        try:
            t0 = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((proxy_ip, proxy_port))
                s.sendall(
                    f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                    f"Host: {target_host}:{target_port}\r\n"
                    f"Connection: close\r\n\r\n".encode())
                resp = ProxyScanner._recv(s)
                if b"200" not in resp.split(b"\r\n", 1)[0]:
                    return (False, 0)
                s.sendall(
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"Connection: close\r\n\r\n".encode())
                page = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    page += chunk
            elapsed = (time.time() - t0) * 1000
            ok = len(page) > 200
            return (ok, elapsed)
        except Exception:
            return (False, 0)

    def verify_proxy(self, ip, port, timeout=3):
        """Test proxy against Baidu and Google. Returns dict."""
        baidu_ok, baidu_ms = self._tunnel_get(
            ip, port, "www.baidu.com", 80, "/", timeout)
        google_ok, google_ms = self._tunnel_get(
            ip, port, "www.google.com", 80, "/", timeout)
        return {
            "baidu": baidu_ok, "baidu_ms": baidu_ms,
            "google": google_ok, "google_ms": google_ms,
        }

    # ---- worker ----

    def _worker(self, timeout):
        while self._running:
            target = self._next_target()
            if target is None:
                break
            ip, port = target
            ptype, conn_ms = ("error", 0)
            try:
                ptype, conn_ms = self._check(ip, port, timeout)
                with self._stats_lock:
                    self.stats["scanned"] += 1
                    if ptype == "ok":
                        self.stats["found"] += 1
                    elif ptype == "auth":
                        self.stats["auth"] += 1
                    elif ptype == "error":
                        self.stats["failed"] += 1
            except Exception:
                with self._stats_lock:
                    self.stats["scanned"] += 1
                    self.stats["failed"] += 1

            now = datetime.now().strftime("%H:%M:%S")
            rec = {"ip": ip, "port": port, "ok": ptype in ("ok", "auth"),
                   "auth": ptype == "auth", "time": now,
                   "conn_ms": round(conn_ms, 1),
                   "baidu": False, "google": False, "type": "unknown"}

            # scan log entry
            log_entry = {
                "ip": ip, "port": port,
                "status": "PROXY" if ptype == "ok" else
                          "AUTH" if ptype == "auth" else
                          "ERROR" if ptype == "error" else "NO",
                "time": now,
                "error": "" if ptype in ("ok", "auth", "no") else
                         f"conn_ms={conn_ms:.0f}",
            }
            with self._scan_log_lock:
                self._scan_log.append(log_entry)

            if ptype in ("ok", "auth"):
                with self._proxies_lock:
                    self._proxies.append(rec)
                if ptype == "auth":
                    self.db.save(rec)
                # queue for auto-verification (only ok, not auth);
                # auth proxies don't need further verification
                if ptype == "ok" and self._verify_running:
                    try:
                        self._verify_queue.put_nowait((ip, port, dict(rec)))
                    except queue.Full:
                        pass

            with self._all_lock:
                if len(self._all) >= self._max_results:
                    self._all.pop(0)
                self._all.append(rec)

            # auto-save state
            now_i = self.stats["scanned"]
            if now_i - self._last_save >= self._save_interval:
                self._last_save = now_i
                self._auto_save()

    # ---- state persistence ----

    def _auto_save(self):
        """Save current scan progress to disk."""
        try:
            state = {
                "version": 2, "ip_start": str(ipaddress.IPv4Address(self._start_int)),
                "ip_end": str(ipaddress.IPv4Address(self._end_int)),
                "ports": self._ports, "next_index": self._next_index,
                "total": self._total, "scanned": self.stats["scanned"],
                "found": self.stats["found"], "auth": self.stats["auth"],
                "failed": self.stats["failed"],
                "exclude_ranges": self._exclude_ranges,
                "exclude_count": self._exclude_count,
                "threads": 200, "timeout": 3.0,
                "timestamp": datetime.now().isoformat(),
            }
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            # also save proxies
            with self._proxies_lock:
                pdata = list(self._proxies)
            with open(PROXIES_FILE, "w") as f:
                json.dump(pdata, f)
        except Exception:
            pass

    def save_state(self, threads, timeout):
        """Full save with options."""
        try:
            state = {
                "version": 2, "ip_start": str(ipaddress.IPv4Address(self._start_int)),
                "ip_end": str(ipaddress.IPv4Address(self._end_int)),
                "ports": self._ports, "next_index": self._next_index,
                "total": self._total, "scanned": self.stats["scanned"],
                "found": self.stats["found"], "auth": self.stats["auth"],
                "failed": self.stats["failed"],
                "exclude_ranges": self._exclude_ranges,
                "exclude_count": self._exclude_count,
                "threads": threads, "timeout": timeout,
                "timestamp": datetime.now().isoformat(),
            }
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            with self._proxies_lock:
                pdata = list(self._proxies)
            with open(PROXIES_FILE, "w") as f:
                json.dump(pdata, f)
        except Exception:
            pass

    @staticmethod
    def has_saved_state():
        return os.path.exists(STATE_FILE)

    @staticmethod
    def load_state():
        """Return (state_dict, proxies_list) or (None, None)."""
        if not os.path.exists(STATE_FILE):
            return (None, None)
        try:
            with open(STATE_FILE) as f:
                state = json.load(f)
            proxies = []
            if os.path.exists(PROXIES_FILE):
                with open(PROXIES_FILE) as f:
                    proxies = json.load(f)
            return (state, proxies)
        except Exception:
            return (None, None)

    @staticmethod
    def clear_saved_state():
        for p in (STATE_FILE, PROXIES_FILE):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

    def resume_from(self, state, proxies):
        """Restore scanner state from saved data."""
        self._start_int = int(ipaddress.IPv4Address(state["ip_start"]))
        self._end_int = int(ipaddress.IPv4Address(state["ip_end"]))
        self._ports = list(state["ports"])
        self._next_index = state.get("next_index", 0)
        self._total = state.get("total", 0)
        self._exclude_ranges = [(s, e) for s, e in state.get("exclude_ranges", [])]
        self._exclude_count = state.get("exclude_count", 0)
        with self._proxies_lock:
            self._proxies = list(proxies)
        with self._stats_lock:
            self.stats.update(
                scanned=state.get("scanned", 0),
                found=state.get("found", 0),
                auth=state.get("auth", 0),
                failed=state.get("failed", 0),
                total=self._total,
                start_time=time.time(),
            )
        # Rebuild _all from proxies (all we have)
        for p in proxies:
            if p.get("ok"):
                with self._all_lock:
                    if len(self._all) >= self._max_results:
                        self._all.pop(0)
                    self._all.append(p)
        # Log to scan_log
        with self._scan_log_lock:
            self._scan_log.append({
                "ip": state["ip_start"], "port": 0,
                "status": "RESUME",
                "time": datetime.now().strftime("%H:%M:%S"),
                "error": f"Resumed at index {self._next_index:,} / {self._total:,}"
            })

    # ---- auto-verify worker ----

    def _verify_worker(self, timeout):
        while True:
            try:
                task = self._verify_queue.get(timeout=1)
            except queue.Empty:
                if not self._verify_running:
                    break
                continue
            if task is None:
                self._verify_queue.task_done()
                break
            self._do_verify(task, timeout)
            self._verify_queue.task_done()

    def _do_verify(self, task, timeout):
        """Verify one proxy; exceptions here won't kill the worker."""
        ip = port = None
        try:
            ip, port, rec = task
            result = self.verify_proxy(ip, port, timeout)
            baidu = result.get("baidu", False)
            google = result.get("google", False)
            conn_ms = result.get("baidu_ms", 0) or result.get("google_ms", 0)
            if google and baidu:
                ptype = "global"
            elif baidu:
                ptype = "china"
            else:
                ptype = "invalid"
            updates = {
                "baidu": baidu, "google": google,
                "conn_ms": round(conn_ms, 1),
                "type": ptype,
                "tested": datetime.now().strftime("%H:%M:%S"),
            }
            merged = {**rec, **updates}
            self.update_proxy(ip, port, updates)
            if baidu or google:
                with self._new_lock:
                    self._verified_new.append(merged)
                self.db.save(merged)
        except Exception as exc:
            with self._scan_log_lock:
                self._scan_log.append({
                    "ip": ip if 'ip' in dir() else "", "port": 0,
                    "status": "VERIFY-ERR",
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "error": str(exc),
                })

    def start_verifiers(self, timeout, count=2):
        self._verify_running = True
        # Drain any stale sentinels left from previous stop
        while True:
            try:
                self._verify_queue.get_nowait()
                self._verify_queue.task_done()
            except queue.Empty:
                break
        self._verify_workers = []
        for _ in range(count):
            t = threading.Thread(target=self._verify_worker,
                                 args=(timeout,), daemon=True)
            t.start()
            self._verify_workers.append(t)

    def stop_verifiers(self):
        self._verify_running = False
        for _ in self._verify_workers:
            self._verify_queue.put(None)
        self._verify_workers = []
        # Drain leftover items (including stale sentinels)
        while True:
            try:
                self._verify_queue.get_nowait()
                self._verify_queue.task_done()
            except queue.Empty:
                break

    # ---- public API ----

    def start(self, ip_start, ip_end, ports, threads=200, timeout=3,
              exclude_ranges=None):
        self._start_int = int(ipaddress.IPv4Address(ip_start))
        self._end_int = int(ipaddress.IPv4Address(ip_end))
        self._ports = list(ports)
        self._next_index = 0
        self._last_save = 0
        n_ips = self._end_int - self._start_int + 1
        self._total = n_ips * len(self._ports)

        self._exclude_ranges = exclude_ranges or []
        excluded_ips = 0
        for s_int, e_int in self._exclude_ranges:
            lo = max(self._start_int, s_int)
            hi = min(self._end_int, e_int)
            if lo <= hi:
                excluded_ips += hi - lo + 1
        self._exclude_count = excluded_ips * len(self._ports)

        eff = self._total - self._exclude_count
        if eff <= 0:
            return

        self._running = True
        self.stats.update(scanned=0, found=0, auth=0, failed=0,
                          total=self._total, start_time=time.time())
        self._workers = []
        n_threads = min(threads, max(1, eff))
        for _ in range(n_threads):
            t = threading.Thread(target=self._worker, args=(timeout,),
                                 daemon=True)
            t.start()
            self._workers.append(t)
        # start auto-verifiers
        self.start_verifiers(timeout, count=min(4, max(1, threads // 10)))

    def stop(self):
        self._running = False
        self.stop_verifiers()
        self._auto_save()

    def clear(self):
        self._running = False
        self.stop_verifiers()
        self._all.clear()
        self._new.clear()
        self._proxies.clear()
        self._scan_log.clear()
        self._exclude_ranges = []
        self._exclude_count = 0
        self.clear_saved_state()
        self._speed_log.clear()
        with self._stats_lock:
            self.stats.update(scanned=0, found=0, auth=0, failed=0,
                              total=0, start_time=0)

    @property
    def running(self):
        return self._running

    @property
    def scan_total(self):
        return self._total - self._exclude_count

    @property
    def progress(self):
        t = self.scan_total
        return 100.0 if t <= 0 else min(100, self.stats["scanned"] / t * 100)

    def speed(self):
        e = time.time() - self.stats["start_time"]
        return 0 if e <= 0 else self.stats["scanned"] / e

    def record_speed(self):
        now = time.time()
        scanned = self.stats["scanned"]
        if self._speed_log and self._speed_log[-1][1] == scanned:
            self._speed_log[-1] = (now, scanned)
        else:
            self._speed_log.append((now, scanned))
        cutoff = now - 60
        self._speed_log = [(t, s) for t, s in self._speed_log if t >= cutoff]

    def recent_speed(self, window=60):
        if len(self._speed_log) < 2:
            return 0
        dt = self._speed_log[-1][0] - self._speed_log[0][0]
        ds = self._speed_log[-1][1] - self._speed_log[0][1]
        return ds / dt if dt > 0 else 0

    def new_results(self):
        with self._new_lock:
            r = list(self._new)
            self._new.clear()
            return r

    def verified_new(self):
        with self._new_lock:
            r = list(self._verified_new)
            self._verified_new.clear()
            return r

    def all_results(self):
        with self._all_lock:
            return list(self._all)

    def proxy_results(self):
        with self._proxies_lock:
            return list(self._proxies)

    def scan_log_snapshot(self):
        with self._scan_log_lock:
            return list(self._scan_log)

    def scan_log_append(self, entry):
        with self._scan_log_lock:
            self._scan_log.append(entry)

    def update_proxy(self, ip, port, updates):
        """Update a specific proxy entry's fields."""
        with self._proxies_lock:
            for p in self._proxies:
                if p["ip"] == ip and p["port"] == port:
                    p.update(updates)
                    break

    def remove_proxy(self, ip, port):
        with self._proxies_lock:
            self._proxies = [p for p in self._proxies
                             if not (p["ip"] == ip and p["port"] == port)]
        self.db.delete(ip, port)


# ====================================================================
# GUI
# ====================================================================

class App:
    def __init__(self, root):
        self.root = root
        root.title(f"HTTP Proxy Scanner v{__version__}")
        root.geometry("1150x850")

        self.sc = ProxyScanner()
        self._row_num = 0

        # tk vars
        self.ip_s      = tk.StringVar(value="8.128.0.0")
        self.ip_e      = tk.StringVar(value="8.191.255.255")
        self.cidr      = tk.StringVar()
        self.ports     = tk.StringVar(
            value="80,1080,2080,3128,3129,4444,5001,8000,8080,8081,8082,8118,8123,8443,8888,8889,9000,9999,10000,10801")
        self.threads   = tk.IntVar(value=200)
        self.timeout   = tk.DoubleVar(value=3.0)
        self.show_all  = tk.BooleanVar(value=False)
        self.status    = tk.StringVar(value="Ready")
        self.vtimeout  = tk.DoubleVar(value=3.0)

        self.exc_private   = tk.BooleanVar(value=True)
        self.exc_loopback  = tk.BooleanVar(value=True)
        self.exc_linklocal = tk.BooleanVar(value=True)
        self.exc_reserved  = tk.BooleanVar(value=True)

        self._build_ui()
        self._current_tab = 0
        self._pp_last_save_count = 0
        self._poll()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        # handle saved state
        self._check_saved_state()

    def _check_saved_state(self):
        state, proxies = ProxyScanner.load_state()
        if state and state.get("version", 1) >= 2:
            self._saved_state = state
            self._saved_proxies = proxies
            self.btn_resume.config(state=tk.NORMAL)
            scanned = state.get("scanned", 0)
            total = state.get("total", 0)
            self.status.set(
                f"Saved scan found: {scanned:,}/{total:,} scanned, "
                f"{len(proxies)} proxies. Click Resume to continue.")
            self.scan_log_append("RESUME", "Saved state loaded, click Resume to continue")
        else:
            self._saved_state = None
            self._saved_proxies = []
            self.btn_resume.config(state=tk.DISABLED)

    def scan_log_append(self, status, msg, ip="", port=0):
        self.sc.scan_log_append({
            "ip": ip, "port": port, "status": status,
            "time": datetime.now().strftime("%H:%M:%S"), "error": msg,
        })

    # ---- GUI layout ----

    def _build_ui(self):
        m = ttk.Frame(self.root, padding=8)
        m.pack(fill=tk.BOTH, expand=True)

        # -- Scan Target --
        sf = ttk.LabelFrame(m, text="Scan Target", padding=8)
        sf.pack(fill=tk.X, pady=(0, 2))

        ttk.Label(sf, text="Start IP:").grid(row=0, column=0)
        ttk.Entry(sf, textvariable=self.ip_s, width=16).grid(
            row=0, column=1, padx=(0, 6))
        ttk.Label(sf, text="End IP:").grid(row=0, column=2, padx=(6, 2))
        ttk.Entry(sf, textvariable=self.ip_e, width=16).grid(
            row=0, column=3, padx=(0, 10))
        ttk.Label(sf, text="CIDR:").grid(row=0, column=4, padx=(0, 2))
        ttk.Entry(sf, textvariable=self.cidr, width=18).grid(
            row=0, column=5, padx=(0, 2))
        ttk.Button(sf, text="\u2190 Apply", command=self._apply_cidr
                   ).grid(row=0, column=6, padx=(0, 8))
        for i, (txt, s, e) in enumerate([
            ("10/8", "10.0.0.0", "10.255.255.255"),
            ("172.16/12", "172.16.0.0", "172.31.255.255"),
            ("192.168/16", "192.168.0.0", "192.168.255.255"),
        ]):
            ttk.Button(sf, text=txt,
                       command=lambda a=s, b=e: (
                           self.ip_s.set(a), self.ip_e.set(b))
                       ).grid(row=0, column=7 + i, padx=1)

        ttk.Label(sf, text="Ports:").grid(row=1, column=0, sticky=tk.W,
                                          pady=(5, 0))
        ttk.Entry(sf, textvariable=self.ports, width=50).grid(
            row=1, column=1, columnspan=6, sticky=tk.W + tk.E,
            padx=(0, 4), pady=(5, 0))
        for i, (txt, p) in enumerate([
            ("Common Ports",
             "80,81,88,443,808,888,1080,1081,2080,3000,3127,3128,3129,4444,5000,5001,6588,7000,7001,7070,7777,8000,8001,8080,8081,8082,8088,8090,8118,8123,8181,8282,8300,8443,8444,8500,8580,8600,8800,8880,8888,8889,8989,9000,9050,9080,9090,9150,9292,9443,9500,9800,9898,9998,9999,10000,10001,10010,10801,18080,20000,31280"),
            ("HTTP/80", "80,81,808,880,8000,8080,8081,8082,8888,9090"),
            ("Squid", "3128,3129,80,8080,443"),
        ]):
            ttk.Button(sf, text=txt,
                       command=lambda v=p: self.ports.set(v)
                       ).grid(row=1, column=7 + i, padx=1, pady=(5, 0))

        ttk.Label(sf, text="Quick Select:").grid(
            row=2, column=0, sticky=tk.W, pady=(5, 0))
        for i, (txt, cs, ce) in enumerate([
            ("AWS (us-east)", "52.0.0.0", "52.63.255.255"),
            ("Azure",         "13.64.0.0", "13.95.255.255"),
            ("Aliyun",        "8.128.0.0", "8.191.255.255"),
            ("GCP",           "34.64.0.0", "34.127.255.255"),
        ]):
            ttk.Button(sf, text=txt,
                       command=lambda a=cs, b=ce: (
                           self.ip_s.set(a), self.ip_e.set(b))
                       ).grid(row=2, column=1 + i, padx=2, pady=(5, 0))

        # -- Exclude IPs --
        xf = ttk.LabelFrame(m, text="Exclude IPs (skip during scan)", padding=6)
        xf.pack(fill=tk.X, pady=(2, 2))
        ttk.Checkbutton(xf, text="Private",
                        variable=self.exc_private).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(xf, text="Loopback",
                        variable=self.exc_loopback).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(xf, text="Link-Local",
                        variable=self.exc_linklocal).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(xf, text="Reserved/Multicast",
                        variable=self.exc_reserved).pack(side=tk.LEFT)

        # -- Scan Control --
        cf = ttk.LabelFrame(m, text="Scan Control", padding=8)
        cf.pack(fill=tk.X, pady=(2, 2))

        ttk.Label(cf, text="Threads:").pack(side=tk.LEFT)
        ttk.Spinbox(cf, from_=1, to=2000, textvariable=self.threads,
                    width=7).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(cf, text="Timeout:").pack(side=tk.LEFT)
        ttk.Spinbox(cf, from_=0.5, to=30, increment=0.5,
                    textvariable=self.timeout, width=6).pack(side=tk.LEFT,
                                                            padx=(0, 10))

        self.btn_start = ttk.Button(cf, text="\u25b6 Start", command=self._start)
        self.btn_start.pack(side=tk.LEFT, padx=2)
        self.btn_stop  = ttk.Button(cf, text="\u25a0 Stop", command=self._stop,
                                    state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=2)
        self.btn_resume = ttk.Button(cf, text="\u21ba Resume", command=self._resume,
                                     state=tk.DISABLED)
        self.btn_resume.pack(side=tk.LEFT, padx=2)
        ttk.Button(cf, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=2)
        ttk.Button(cf, text="Export", command=self._export).pack(side=tk.LEFT, padx=2)

        # -- Progress --
        pf = ttk.LabelFrame(m, text="Progress", padding=8)
        pf.pack(fill=tk.X, pady=(2, 2))

        pbar_frame = ttk.Frame(pf)
        pbar_frame.pack(fill=tk.X)
        self.pbar = ttk.Progressbar(pbar_frame, mode="determinate")
        self.pbar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.lbl_pct = ttk.Label(pbar_frame, text="0%", width=8)
        self.lbl_pct.pack(side=tk.LEFT, padx=(6, 0))

        sf2 = ttk.Frame(pf)
        sf2.pack(fill=tk.X, pady=(3, 0))
        self.lbl_stats = ttk.Label(sf2,
            text="Scanned: 0  |  Found: 0  |  Auth: 0  |  "
                 "Excluded: 0  |  Speed: 0/s")
        self.lbl_stats.pack(side=tk.LEFT)
        self.lbl_time = ttk.Label(sf2,
            text="Elapsed: 00:00:00  |  Remaining: --:--:--")
        self.lbl_time.pack(side=tk.RIGHT)

        # -- Bottom: Notebook --
        nb = ttk.Notebook(m)
        nb.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        nb.bind("<<NotebookTabChanged>>", self._on_tab_change)
        self._notebook = nb

        # ===== TAB 1: Results (unchanged) =====
        rf = ttk.Frame(nb, padding=4)
        nb.add(rf, text="  Results  ")

        cols = ("#", "IP", "Port", "Status", "Conn(ms)", "Time")
        self.tree = ttk.Treeview(rf, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("#", width=40, anchor=tk.CENTER)
        self.tree.column("IP", width=135)
        self.tree.column("Port", width=60, anchor=tk.CENTER)
        self.tree.column("Status", width=90, anchor=tk.CENTER)
        self.tree.column("Conn(ms)", width=70, anchor=tk.CENTER)
        self.tree.column("Time", width=80, anchor=tk.CENTER)
        vsb = ttk.Scrollbar(rf, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.tag_configure("proxy",   foreground="#006600",
                                font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("auth",    foreground="#cc6600",
                                font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("global",  foreground="#006600",
                                font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("china",   foreground="#cc6600")
        self.tree.tag_configure("invalid", foreground="#cc0000")
        self.tree.tag_configure("noproxy", foreground="#999999")
        self.tree.bind("<Double-1>", self._copy_ip)
        ttk.Checkbutton(rf, text=f"Show all results (max {MAX_TREE_ITEMS:,})",
                        variable=self.show_all,
                        command=self._refresh).pack(anchor=tk.W)

        # ===== TAB 2: Scan Log (results table) =====
        lf = ttk.Frame(nb, padding=4)
        nb.add(lf, text="  Scan Log  ")

        llab = ttk.Label(lf, text=f"Last {MAX_LOG_LINES} scan results / errors",
                         font=("", 9, ""))
        llab.pack(anchor=tk.W)

        log_cols = ("IP", "Port", "Status", "Time", "Info")
        self.log_tree = ttk.Treeview(lf, columns=log_cols, show="headings",
                                     height=14)
        for c in log_cols:
            self.log_tree.heading(c, text=c)
        self.log_tree.column("IP", width=140)
        self.log_tree.column("Port", width=65, anchor=tk.CENTER)
        self.log_tree.column("Status", width=80, anchor=tk.CENTER)
        self.log_tree.column("Time", width=75, anchor=tk.CENTER)
        self.log_tree.column("Info", width=350)
        log_vsb = ttk.Scrollbar(lf, orient=tk.VERTICAL,
                                command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=log_vsb.set)
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_tree.tag_configure("PROXY", foreground="#006600",
                                    font=("Segoe UI", 9, "bold"))
        self.log_tree.tag_configure("AUTH", foreground="#cc6600",
                                    font=("Segoe UI", 9, "bold"))
        self.log_tree.tag_configure("ERROR", foreground="#cc0000")
        self.log_tree.tag_configure("NO", foreground="#999999")
        self.log_tree.tag_configure("RESUME", foreground="#0066cc")
        self._log_tree_items = 0

        # ===== TAB 3: Proxy Pool =====
        ppf = ttk.Frame(nb, padding=4)
        nb.add(ppf, text="  Proxy Pool  ")

        # control bar
        pp_ctl = ttk.Frame(ppf)
        pp_ctl.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(pp_ctl, text="Verify Timeout:").pack(side=tk.LEFT)
        ttk.Spinbox(pp_ctl, from_=1, to=30, increment=0.5,
                    textvariable=self.vtimeout, width=6).pack(side=tk.LEFT,
                                                              padx=(0, 10))
        self.btn_verify_sel = ttk.Button(pp_ctl, text="Verify Selected",
                                         command=self._verify_selected)
        self.btn_verify_sel.pack(side=tk.LEFT, padx=2)
        self.btn_verify_all = ttk.Button(pp_ctl, text="Verify All",
                                         command=self._verify_all)
        self.btn_verify_all.pack(side=tk.LEFT, padx=2)
        ttk.Button(pp_ctl, text="Remove Selected",
                   command=self._remove_proxy).pack(side=tk.LEFT, padx=2)
        ttk.Button(pp_ctl, text="Export Proxies",
                   command=self._export_proxies).pack(side=tk.LEFT, padx=2)
        ttk.Button(pp_ctl, text="Remove All",
                   command=self._remove_all_proxies).pack(side=tk.LEFT, padx=2)

        pp_cols = ("IP", "Port", "Status", "Conn(ms)", "Google", "Baidu",
                   "Tested")
        self.pp_tree = ttk.Treeview(ppf, columns=pp_cols, show="headings",
                                    height=14)
        for c in pp_cols:
            self.pp_tree.heading(c, text=c)
        self.pp_tree.column("IP", width=135)
        self.pp_tree.column("Port", width=60, anchor=tk.CENTER)
        self.pp_tree.column("Status", width=60, anchor=tk.CENTER)
        self.pp_tree.column("Conn(ms)", width=70, anchor=tk.CENTER)
        self.pp_tree.column("Google", width=65, anchor=tk.CENTER)
        self.pp_tree.column("Baidu", width=65, anchor=tk.CENTER)
        self.pp_tree.column("Tested", width=80, anchor=tk.CENTER)
        pp_vsb = ttk.Scrollbar(ppf, orient=tk.VERTICAL,
                               command=self.pp_tree.yview)
        self.pp_tree.configure(yscrollcommand=pp_vsb.set)
        self.pp_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pp_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.pp_tree.tag_configure("global", foreground="#006600",
                                   font=("Segoe UI", 9, "bold"))
        self.pp_tree.tag_configure("china", foreground="#cc6600")
        self.pp_tree.tag_configure("invalid", foreground="#cc0000")
        self.pp_tree.tag_configure("auth", foreground="#cc6600",
                                   font=("Segoe UI", 9, "bold"))
        self.pp_tree.tag_configure("proxy", foreground="#006600",
                                   font=("Segoe UI", 9, "bold"))

        # Status bar
        ttk.Label(self.root, textvariable=self.status,
                  relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, side=tk.BOTTOM)

    # ---- actions ----

    def _apply_cidr(self):
        raw = self.cidr.get().strip()
        if not raw:
            return
        try:
            net = ipaddress.IPv4Network(raw, strict=False)
            self.ip_s.set(str(net.network_address))
            self.ip_e.set(str(net.broadcast_address))
            self.status.set(f"CIDR {raw} applied")
            self.scan_log_append("INFO", f"CIDR {raw} applied", raw)
        except ValueError as e:
            messagebox.showerror("Invalid CIDR", str(e))

    def _collect_exclude_ranges(self):
        ranges = []
        mapping = {"private": self.exc_private, "loopback": self.exc_loopback,
                   "linklocal": self.exc_linklocal, "reserved": self.exc_reserved}
        for key, var in mapping.items():
            if var.get():
                for s, e in EXCLUDE_PRESETS[key]:
                    try:
                        si = int(ipaddress.IPv4Address(s))
                        ei = int(ipaddress.IPv4Address(e))
                        ranges.append((si, ei))
                    except ipaddress.AddressValueError:
                        pass
        if not ranges:
            return []
        ranges.sort()
        merged = [ranges[0]]
        for s, e in ranges[1:]:
            if s <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        return merged

    def _start(self):
        try:
            a = ipaddress.IPv4Address(self.ip_s.get().strip())
            b = ipaddress.IPv4Address(self.ip_e.get().strip())
        except ipaddress.AddressValueError as e:
            messagebox.showerror("Invalid IP", str(e))
            return
        if int(b) < int(a):
            messagebox.showerror("Invalid Range", "End IP must be >= Start IP")
            return
        ports = parse_ports(self.ports.get().strip())
        if not ports:
            messagebox.showerror("Invalid Ports",
                                 "Enter ports like 80,8080 or 1-1024")
            return

        total_ip = int(b) - int(a) + 1
        total_raw = total_ip * len(ports)
        exclude = self._collect_exclude_ranges()
        excluded_ips = 0
        for s_int, e_int in exclude:
            lo = max(int(a), s_int)
            hi = min(int(b), e_int)
            if lo <= hi:
                excluded_ips += hi - lo + 1
        total_eff = total_raw - excluded_ips * len(ports)

        if total_eff <= 0:
            messagebox.showwarning("Nothing to Scan", "All targets excluded.")
            return
        if total_raw > 1_000_000 and not messagebox.askyesno(
                "Large Scan",
                f"Raw: {total_raw:,}  Effective: {total_eff:,}\nContinue?"):
            return

        # clear old saved state
        ProxyScanner.clear_saved_state()
        self._saved_state = None
        self._saved_proxies = []
        self.btn_resume.config(state=tk.DISABLED)

        self.sc.clear()
        self.tree.delete(*self.tree.get_children())
        self.log_tree.delete(*self.log_tree.get_children())
        self._row_num = 0
        self._log_tree_items = 0

        self.scan_log_append("INFO", f"Scan started: {a} - {b}, "
                             f"{total_eff:,} targets, {self.threads.get()} threads")

        self.sc.start(a, b, ports, self.threads.get(), self.timeout.get(),
                      exclude_ranges=exclude)
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_resume.config(state=tk.DISABLED)
        self.status.set(f"Scanning {total_eff:,} targets ...")

    def _stop(self):
        self.sc.stop()
        self.sc.save_state(self.threads.get(), self.timeout.get())
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status.set("Scan stopped. State saved. Click Resume to continue.")
        self.scan_log_append("STOP", "Scan stopped by user, state saved")
        # re-check for resume
        self._check_saved_state()

    def _resume(self):
        if not self._saved_state:
            return
        state = self._saved_state
        proxies = self._saved_proxies

        thr = self.threads.get()
        to = self.timeout.get()

        self.sc.clear()
        self.tree.delete(*self.tree.get_children())
        self.log_tree.delete(*self.log_tree.get_children())
        self._row_num = len(proxies)
        self._log_tree_items = 0

        self.sc.resume_from(state, proxies)
        # Don't pre-fill Results; they will appear after auto-verification

        # Restore input fields
        self.ip_s.set(state["ip_start"])
        self.ip_e.set(state["ip_end"])
        self.ports.set(",".join(str(p) for p in state["ports"]))
        self.exc_private.set(True)
        self.exc_loopback.set(True)
        self.exc_linklocal.set(True)
        self.exc_reserved.set(True)

        # Start worker threads WITHOUT resetting _next_index (start() would)
        eff = self.sc._total - self.sc._exclude_count
        n_threads = min(thr, max(1, eff))
        self.sc._running = True
        self.sc._workers = []
        for _ in range(n_threads):
            t = threading.Thread(target=self.sc._worker, args=(to,), daemon=True)
            t.start()
            self.sc._workers.append(t)
        self.sc.start_verifiers(to, count=min(4, max(1, thr // 10)))
        remaining = self.sc._total - self.sc._exclude_count - self.sc.stats["scanned"]
        self.scan_log_append("RESUME",
            f"Resumed scan, {remaining:,} targets remaining",
            state["ip_start"])
        self.status.set(f"Resumed scanning ...")

        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_resume.config(state=tk.DISABLED)
        self._saved_state = None
        self._saved_proxies = []
        pct = self.sc.progress
        self.pbar["value"] = pct
        self.lbl_pct.config(text=f"{pct:.1f}%" if pct else "0%")

        eff = state.get("total", 0) - state.get("exclude_count", 0)
        scanned = state.get("scanned", 0)
        self.status.set(
            f"Resumed: {scanned:,}/{eff:,} done, continuing ...")
        self.scan_log_append("RESUME", f"Resumed from index {state.get('next_index', 0):,} "
                             f"/ {state.get('total', 0):,}")

    def _clear(self):
        if self.sc.running:
            if not messagebox.askyesno("Clear", "Scan running. Stop & clear?"):
                return
            self.sc.stop()
        elif self.sc.stats["scanned"] or self.sc.db.count():
            if not messagebox.askyesno("Clear", "Clear all scan data and database?"):
                return
        self.sc.clear()
        self.sc.db.clear()
        self.tree.delete(*self.tree.get_children())
        self.log_tree.delete(*self.log_tree.get_children())
        self._update_pp_tree()
        self._row_num = 0
        self._log_tree_items = 0
        self._saved_state = None
        self._saved_proxies = []
        self.btn_resume.config(state=tk.DISABLED)
        self.lbl_stats.config(
            text="Scanned: 0  |  Found: 0  |  Auth: 0  |  "
                 "Excluded: 0  |  Speed: 0/s")
        self.lbl_time.config(
            text="Elapsed: 00:00:00  |  Remaining: --:--:--")
        self.pbar["value"] = 0
        self.lbl_pct.config(text="0%")
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status.set("Ready")

    def _export(self):
        proxies = [p for p in self.sc.proxy_results()
                   if p.get("baidu") or p.get("google") or p.get("auth")]
        if not proxies:
            messagebox.showinfo("Export", "No proxies found")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["IP", "Port", "Status", "Conn(ms)", "Google",
                            "Baidu", "Time"])
                for r in proxies:
                    _, st = self._status_and_tag(r)
                    w.writerow([
                        r["ip"], r["port"], st,
                        r.get("conn_ms", ""),
                        "Pass" if r.get("google") else "Fail",
                        "Pass" if r.get("baidu") else "Fail",
                        r["time"],
                    ])
            self.status.set(f"Exported {len(proxies)} proxies")
            self.scan_log_append("EXPORT", f"Exported {len(proxies)} proxies",
                                 os.path.basename(path))
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _export_proxies(self):
        self._export()

    # ---- Proxy Pool actions ----

    def _update_pp_tree(self):
        # save selection
        sel = {}
        for iid in self.pp_tree.selection():
            v = self.pp_tree.item(iid, "values")
            if v:
                sel[(v[0], v[1])] = True
        self.pp_tree.delete(*self.pp_tree.get_children())
        rows = list(self.sc.db.load_all())
        rows.sort(key=lambda r: r.get("tested") or r.get("discovered") or "", reverse=True)
        for r in rows:
            self._insert_pp_row(r)
        # restore selection
        for child in self.pp_tree.get_children():
            v = self.pp_tree.item(child, "values")
            if v and (v[0], v[1]) in sel:
                self.pp_tree.selection_add(child)

    def _insert_pp_row(self, p):
        tag, st = self._status_and_tag(p)
        conn = p.get("conn_ms", 0)
        google = "Pass" if p.get("google") else "Fail"
        baidu = "Pass" if p.get("baidu") else "Fail"
        tested = p.get("tested", "")
        self.pp_tree.insert("", tk.END,
                            values=(p["ip"], p["port"], st, conn,
                                    google, baidu, tested),
                            tags=(tag,))

    def _verify_single(self, proxy):
        ip, port = proxy["ip"], proxy["port"]
        to = self.vtimeout.get()
        result = self.sc.verify_proxy(ip, port, to)
        conn_ms = result.get("baidu_ms", 0) or result.get("google_ms", 0)
        baidu = result["baidu"]
        google = result["google"]

        if google and baidu:
            ptype = "global"
        elif baidu:
            ptype = "china"
        else:
            ptype = "invalid"

        updates = {
            "baidu": baidu, "google": google,
            "conn_ms": round(conn_ms, 1),
            "type": ptype,
            "tested": datetime.now().strftime("%H:%M:%S"),
        }
        self.sc.update_proxy(ip, port, updates)
        self.sc.db.save({**proxy, **updates})
        return updates

    def _verify_tree_items(self, items):
        """Build proxy dicts from tree items."""
        result = []
        for item in items:
            vals = self.pp_tree.item(item, "values")
            result.append({
                "ip": vals[0],
                "port": int(vals[1]),
                "ok": True, "auth": False,
                "conn_ms": 0, "type": "", "time": "",
            })
        return result

    def _verify_selected(self):
        sel = self.pp_tree.selection()
        if not sel:
            messagebox.showinfo("Verify", "Select proxies in the Pool tab")
            return
        items = self._verify_tree_items(sel)
        self.status.set(f"Verifying {len(items)} proxies ...")
        threading.Thread(target=self._batch_verify, args=(items,),
                         daemon=True).start()

    def _verify_all(self):
        items = self._verify_tree_items(self.pp_tree.get_children())
        if not items:
            return
        self.status.set(f"Verifying {len(items)} proxies ...")
        threading.Thread(target=self._batch_verify, args=(items,),
                         daemon=True).start()

    def _batch_verify(self, proxies):
        """Background thread: verify a list of proxies without blocking UI."""
        total = len(proxies)
        for i, p in enumerate(proxies, 1):
            self._verify_single(p)
            if i % 5 == 0 or i == total:
                self.root.after(0, lambda i=i, t=total: self.status.set(
                    f"Verifying {i}/{t} ..."))
        self.root.after(0, self._on_batch_done)

    def _on_batch_done(self):
        self._update_pp_tree()
        self._refresh()
        self.status.set("Verification complete")

    def _remove_proxy(self):
        sel = self.pp_tree.selection()
        if not sel:
            return
        if not messagebox.askyesno("Remove",
                                   f"Remove {len(sel)} proxy/proxies from database?"):
            return
        for item in sel:
            vals = self.pp_tree.item(item, "values")
            ip, port = vals[0], int(vals[1])
            self.sc.remove_proxy(ip, port)
        self._update_pp_tree()
        self._refresh()
        self.status.set(f"Removed {len(sel)} proxy/proxies")

    def _remove_all_proxies(self):
        proxies = [p for p in self.sc.proxy_results()
                   if p.get("baidu") or p.get("google") or p.get("auth")]
        if not proxies:
            return
        if not messagebox.askyesno("Remove All",
                                   f"Remove all {len(proxies)} proxies?"):
            return
        for p in proxies:
            self.sc.remove_proxy(p["ip"], p["port"])
        self._update_pp_tree()
        self._refresh()

    def _status_and_tag(self, r):
        """Determine display status & tag from proxy record."""
        if r.get("auth"):
            return ("auth", "Auth")
        ptype = r.get("type", "")
        if ptype == "global":
            return ("global", "Global")
        if ptype == "china":
            return ("china", "China")
        if ptype == "invalid":
            return ("invalid", "Invalid")
        if r.get("ok"):
            return ("proxy", "Proxy")
        return ("noproxy", "No")

    def _on_tab_change(self, event=None):
        """When Proxy Pool tab is selected, load from DB."""
        if not hasattr(self, "_notebook"):
            return
        try:
            self._current_tab = self._notebook.index(self._notebook.select())
            # tab 2 = Proxy Pool (0=Results, 1=Scan Log, 2=Proxy Pool)
            if self._current_tab == 2:
                self._pp_last_save_count = self.sc.db._save_count
                self._update_pp_tree()
        except Exception:
            pass

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        self._row_num = 0
        q = [p for p in self.sc.proxy_results()
             if p.get("baidu") or p.get("google")]
        if self.show_all.get() and len(q) > MAX_TREE_ITEMS:
            q = q[:MAX_TREE_ITEMS]
        for r in q:
            self._row_num += 1
            if self._row_num > MAX_TREE_ITEMS:
                break
            tag, st = self._status_and_tag(r)
            conn = r.get("conn_ms", "")
            self.tree.insert("", tk.END,
                             values=(self._row_num, r["ip"], r["port"],
                                     st, conn, r["time"]), tags=(tag,))

    def _copy_ip(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        v = self.tree.item(sel[0], "values")
        ip, port = v[1], v[2]
        self.root.clipboard_clear()
        self.root.clipboard_append(f"{ip}:{port}")
        self.status.set(f"Copied {ip}:{port}")

    # ---- polling ----

    @staticmethod
    def _fmt_seconds(secs):
        secs = int(max(0, secs))
        h, m = divmod(secs, 3600)
        m, s = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _poll(self):
        # --- Results tab: only show verified proxies ---
        for r in self.sc.verified_new():
            self._row_num += 1
            tag, st = self._status_and_tag(r)
            conn = r.get("conn_ms", "")
            self.tree.insert("", tk.END,
                             values=(self._row_num, r["ip"], r["port"],
                                     st, conn, r["time"]), tags=(tag,))
            try:
                self.tree.see(self.tree.get_children()[-1])
            except IndexError:
                pass

        # --- Scan Log tab ---
        log = self.sc.scan_log_snapshot()
        if len(log) != self._log_tree_items:
            self.log_tree.delete(*self.log_tree.get_children())
            for entry in log:
                tag = entry.get("status", "NO")
                self.log_tree.insert("", tk.END,
                                     values=(entry["ip"], entry["port"],
                                             entry["status"], entry["time"],
                                             entry.get("error", "")),
                                     tags=(tag,))
            self._log_tree_items = len(log)

        # --- Proxy Pool tab (refresh on DB save) ---
        if self._current_tab == 2:
            cnt = self.sc.db._save_count
            if cnt != self._pp_last_save_count:
                self._pp_last_save_count = cnt
                self._update_pp_tree()

        # --- Speed sampling ---
        self.sc.record_speed()

        # --- Progress ---
        s = self.sc.stats
        pct = self.sc.progress
        self.pbar["value"] = pct
        self.lbl_pct.config(text=f"{pct:.1f}%" if s["scanned"] else "0%")
        excluded = self.sc._exclude_count
        verified = sum(1 for p in self.sc.proxy_results()
                       if p.get("baidu") or p.get("google"))
        self.lbl_stats.config(
            text=f"Scanned: {s['scanned']:,} / {self.sc.scan_total:,}  |  "
                 f"Found: {s['found']:,}  |  "
                 f"Auth: {s['auth']:,}  |  "
                 f"Verified: {verified:,}  |  "
                 f"Excluded: {excluded:,}  |  "
                 f"Speed: {self.sc.speed():.0f}/s")

        if s["start_time"] and s["scanned"]:
            el = time.time() - s["start_time"]
            el_s = self._fmt_seconds(el)
            spd = self.sc.recent_speed()
            if spd <= 0:
                spd = self.sc.speed()
            remaining = s["total"] - excluded - s["scanned"]
            rem_s = (self._fmt_seconds(max(0, remaining) / spd)
                     if spd > 0 and remaining > 0 else "--:--:--")
            self.lbl_time.config(
                text=f"Elapsed: {el_s}  |  Remaining: {rem_s}")

        # --- Completion ---
        if self.sc.running and s["scanned"] >= self.sc.scan_total > 0:
            self.sc.stop()
            self.sc.save_state(self.threads.get(), self.timeout.get())
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            el = time.time() - s["start_time"]
            elapsed_s = time.strftime("%H:%M:%S", time.gmtime(el))
            self.scan_log_append("COMPLETE",
                f"Scan completed: {s['found']} proxies, "
                f"{s['auth']} auth, in {elapsed_s}")
            self.status.set(
                f"Complete \u2014 {s['found']} proxies + "
                f"{s['auth']} auth in {elapsed_s}")

        self.root.after(250, self._poll)

    def _on_close(self):
        if self.sc.running:
            self.sc.save_state(self.threads.get(), self.timeout.get())
            self.sc.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
