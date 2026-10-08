"""The browser app: a small web server that only listens on this computer."""

import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import __version__
from .engine import (IS_WINDOWS, Cancelled, CopyJob, ScanJob, clean_dest, safe_name)

if IS_WINDOWS:
    try:   # no "insert a disk" popups when probing empty card readers
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x8000)
    except Exception:
        pass


def load_page():
    return resources.files("stragglers").joinpath("ui.html").read_text(encoding="utf-8")


# ----------------------------------------------------------------------------
# Drives and folder pickers, per operating system
# ----------------------------------------------------------------------------

def volume_label(root):
    if not IS_WINDOWS:
        return os.path.basename(root.rstrip("/")) or "System"
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), buf, 261, None, None, None, None, 0)
        return buf.value if ok else ""
    except Exception:
        return ""


def list_drives():
    roots = []
    if IS_WINDOWS:
        if hasattr(os, "listdrives"):
            roots = os.listdrives()
        else:
            roots = [f"{c}:\\" for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{c}:\\")]
    elif sys.platform == "darwin":
        try:
            for n in sorted(os.listdir("/Volumes")):
                p = os.path.join("/Volumes", n)
                # the startup disk shows up here as a link to "/"
                if os.path.isdir(p) and not (os.path.islink(p) and os.path.realpath(p) == "/"):
                    roots.append(p)
        except OSError:
            pass
        roots.append(os.path.expanduser("~"))
    else:
        for base in ("/media", "/run/media", "/mnt"):
            try:
                for n in sorted(os.listdir(base)):
                    p = os.path.join(base, n)
                    if os.path.isdir(p):
                        if base != "/mnt" and not os.path.ismount(p):
                            roots.extend(os.path.join(p, m) for m in sorted(os.listdir(p)))
                        else:
                            roots.append(p)
            except OSError:
                pass
        roots.append(os.path.expanduser("~"))
    out = []
    for r in roots:
        try:
            u = shutil.disk_usage(r)
        except OSError:
            continue
        label = "Home folder" if r == os.path.expanduser("~") else volume_label(r)
        out.append({"path": r, "label": label, "total": u.total, "used": u.used,
                    "free": u.free, "writable": os.access(r, os.W_OK)})
    return out


def pick_folder():
    """Open the system's own folder picker. Returns a path or None."""
    if sys.platform == "darwin":
        # AppleScript, because Tk windows must live on the main thread on macOS
        r = subprocess.run(["osascript", "-e",
                            'POSIX path of (choose folder with prompt "Choose a folder")'],
                           capture_output=True, text=True)
        return r.stdout.strip().rstrip("/") or None if r.returncode == 0 else None
    if not IS_WINDOWS and shutil.which("zenity"):
        r = subprocess.run(["zenity", "--file-selection", "--directory"], capture_output=True, text=True)
        return r.stdout.strip() or None
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title="Choose a folder", mustexist=True)
    root.destroy()
    return os.path.normpath(path) if path else None


def reveal(path):
    if IS_WINDOWS:
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


# ----------------------------------------------------------------------------
# App state
# ----------------------------------------------------------------------------

class App:
    def __init__(self, data_dir):
        self.data_dir = os.path.abspath(data_dir)
        self.lock = threading.Lock()
        self.job = None
        self.plan = None
        self.run_dir = None
        self.copy_result = None

    def busy(self):
        return self.job is not None and self.job["state"] == "running"

    def _start(self, kind, obj, finish):
        job = {"kind": kind, "obj": obj, "state": "running", "error": None}

        def target():
            try:
                res = obj.run()
                finish(res)
                job["state"] = "done"
            except Cancelled:
                job["state"] = "cancelled"
            except Exception as e:
                job["state"] = "failed"
                job["error"] = f"{type(e).__name__}: {e}"
            finally:
                if kind == "copy" and self.copy_result is None:
                    self.copy_result = {"counts": dict(obj.counts), "stopped": obj.stopped_reason}
        self.job = job
        threading.Thread(target=target, daemon=True).start()

    def start_scan(self, body):
        with self.lock:
            if self.busy():
                raise ValueError("Something is already running.")
            job = ScanJob(body.get("source"), body.get("target"), body.get("label"),
                          self.data_dir, thorough=bool(body.get("thorough")),
                          include_hidden=bool(body.get("include_hidden")))
            job.validate()
            self.plan, self.copy_result = None, None

            def finish(plan):
                self.plan, self.run_dir = plan, job.run_dir
            self._start("scan", job, finish)

    def start_copy(self, body):
        with self.lock:
            if self.busy():
                raise ValueError("Something is already running.")
            if not self.plan:
                raise ValueError("Run a scan first.")
            by_id = {b["id"]: b for b in self.plan["blocks"]}
            decisions = []
            for d in body.get("decisions", []):
                b = by_id.get(int(d["id"]))
                if b:
                    decisions.append((b, clean_dest(d.get("dest", ""), self.plan["target_root"])))
            if not decisions:
                raise ValueError("Nothing is selected.")
            for p in (self.plan["source_root"], self.plan["target_root"]):
                if not os.path.isdir(p):
                    raise ValueError(f"Not connected: {p}")
            if not os.access(self.plan["target_root"], os.W_OK):
                raise ValueError(f"{self.plan['target_root']} is read-only on this computer, so nothing "
                                 "can be copied to it. On a Mac this usually means the drive is "
                                 "formatted as NTFS.")
            cj = CopyJob(self.plan, decisions, self.run_dir, verify=bool(body.get("verify")),
                         skip_repeats=body.get("skip_repeats", True) is not False)
            self.copy_result = None

            def finish(counts):
                self.copy_result = {"counts": dict(counts), "stopped": cj.stopped_reason}
            self._start("copy", cj, finish)

    def status(self):
        j = self.job
        out = {"job": None, "has_plan": self.plan is not None, "copy_result": self.copy_result}
        if j:
            obj = j["obj"]
            out["job"] = {"kind": j["kind"], "state": j["state"], "error": j["error"],
                          "progress": obj.progress.snap()}
            if j["kind"] == "scan":
                out["job"]["source"], out["job"]["target"] = obj.src, obj.tgt
            else:
                out["job"]["target"] = obj.plan["target_root"]
        return out

    def result(self):
        p = self.plan
        light = [{k: v for k, v in b.items() if k not in ("files", "dup_files")} for b in p["blocks"]]
        try:
            u = shutil.disk_usage(p["target_root"])
            free, writable = u.free, os.access(p["target_root"], os.W_OK)
        except OSError:
            free, writable = None, False
        return {"source_root": p["source_root"], "target_root": p["target_root"],
                "label": p["source_label"], "created": p["created"], "mode": p.get("mode"),
                "elapsed": p.get("elapsed", 0), "errors": p.get("errors", 0),
                "totals": p["totals"], "categories": p["categories"],
                "relocated": p["relocated"][:200], "relocated_count": len(p["relocated"]),
                "blocks": light, "target_free": free, "target_writable": writable,
                "archive_root": f"From {safe_name(p['source_label'])}", "sep": os.sep}

    def block_files(self, bid):
        b = next((b for b in self.plan["blocks"] if b["id"] == bid), None)
        if not b:
            raise ValueError("Unknown item.")
        return {"files": [[r, s, r in b["dup_files"]] for r, s in b["files"][:1000]], "count": b["count"]}

    def history(self):
        out = []
        scans = os.path.join(self.data_dir, "scans")
        try:
            names = sorted(os.listdir(scans), reverse=True)
        except OSError:
            return out
        for n in names:
            mp = os.path.join(scans, n, "meta.json")
            if os.path.isfile(mp):
                try:
                    with open(mp, encoding="utf-8") as f:
                        m = json.load(f)
                    m["run"] = n
                    out.append(m)
                except (OSError, ValueError):
                    pass
            if len(out) >= 12:
                break
        return out

    def load(self, run):
        with self.lock:
            if self.busy():
                raise ValueError("Something is already running.")
            if not run or "/" in run or "\\" in run or run.startswith("."):
                raise ValueError("Unknown scan.")
            d = os.path.join(self.data_dir, "scans", run)
            with open(os.path.join(d, "plan.json"), encoding="utf-8") as f:
                plan = json.load(f)
            if plan.get("app") != "stragglers" or plan.get("version") != 3:
                raise ValueError("That scan was made by an older version. Please scan again.")
            self.plan, self.run_dir, self.copy_result, self.job = plan, d, None, None


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

def make_handler(app, token, page, server_ref):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"stragglers/{__version__}"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(data)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj))

        def _ok_host(self):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            return host in ("127.0.0.1", "localhost")

        def _authed(self):
            return self._ok_host() and secrets.compare_digest(self.headers.get("X-Token", ""), token)

        def do_GET(self):
            u = urlparse(self.path)
            if not self._ok_host():
                return self._send(403, "forbidden", "text/plain")
            if u.path == "/":
                return self._send(200, page, "text/html; charset=utf-8")
            if not self._authed():
                return self._json({"error": "forbidden"}, 403)
            try:
                if u.path == "/api/drives":
                    return self._json({"drives": list_drives(), "version": __version__,
                                       "platform": sys.platform})
                if u.path == "/api/status":
                    return self._json(app.status())
                if u.path == "/api/result":
                    if not app.plan:
                        return self._json({"error": "No scan yet."}, 404)
                    return self._json(app.result())
                if u.path == "/api/block":
                    bid = int(parse_qs(u.query).get("id", ["0"])[0])
                    return self._json(app.block_files(bid))
                if u.path == "/api/history":
                    return self._json({"runs": app.history()})
            except Exception as e:
                return self._json({"error": str(e)}, 500)
            self._json({"error": "not found"}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            if not self._authed():
                return self._json({"error": "forbidden"}, 403)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json({"error": "bad request"}, 400)
            try:
                if u.path == "/api/scan":
                    app.start_scan(body)
                elif u.path == "/api/copy":
                    app.start_copy(body)
                elif u.path == "/api/cancel":
                    if app.job:
                        app.job["obj"].cancel.set()
                elif u.path == "/api/load":
                    app.load(body.get("run"))
                elif u.path == "/api/close":
                    with app.lock:
                        if not app.busy():
                            app.plan, app.job, app.copy_result = None, None, None
                elif u.path == "/api/browse":
                    try:
                        return self._json({"path": pick_folder()})
                    except Exception:
                        return self._json({"error": "The folder picker is not available here. "
                                                    "Type the path instead."}, 400)
                elif u.path == "/api/reveal":
                    target = app.run_dir if body.get("what") == "scan" else app.data_dir
                    if not target:
                        return self._json({"error": "No scan yet."}, 400)
                    reveal(target)
                elif u.path == "/api/quit":
                    self._json({"ok": True})
                    threading.Thread(target=server_ref[0].shutdown, daemon=True).start()
                    return
                else:
                    return self._json({"error": "not found"}, 404)
            except (ValueError, OSError) as e:
                return self._json({"error": str(e)}, 400)
            self._json({"ok": True})

    return Handler


def serve(data_dir, port=8765, open_browser=True):
    app = App(data_dir)
    token = secrets.token_urlsafe(18)
    server_ref = [None]
    handler = make_handler(app, token, load_page(), server_ref)
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    server_ref[0] = srv
    url = f"http://127.0.0.1:{srv.server_address[1]}/#t={token}"
    print(f"\n  stragglers {__version__} is running at\n  {url}\n")
    print("  It opens in your browser. To stop it, click Quit in the page or press Ctrl+C here.\n")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    if app.busy():
        app.job["obj"].cancel.set()
    srv.server_close()
    print("  Stopped.")
