"""Scanning, matching, reporting and copying.

Everything here is standard library only and runs on the caller's thread,
except the hashing pool, which reads files in parallel.
"""

import csv
import datetime as dt
import hashlib
import itertools
import json
import os
import shutil
import sqlite3
import sys
import threading
import time
import unicodedata
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------

CHUNK_SIZE = 1024 * 1024          # read buffer for full hashes
COPY_CHUNK = 4 * 1024 * 1024      # copy buffer
QUICK_SIZE = 64 * 1024            # head and tail sample for the quick fingerprint
SMALL_LIMIT = 2 * QUICK_SIZE      # at or below this, the quick hash covers the whole file
BIG_FILE = 1024 * 1024            # fast mode compares against every same-size file from here up
META_ANYNAME_MIN = 1024 * 1024    # size+date match under a different name only from here up
QUICK_WORKERS = 12                # parallel small reads
FULL_WORKERS = 4                  # parallel large reads (more makes spinning disks thrash)
IS_WINDOWS = os.name == "nt"
PARTIAL_SUFFIX = ".stragglers-part"
MAX_REPORT_ITEMS_PER_GROUP = 40

SKIP_DIRS = {
    "$recycle.bin", "recycler", "system volume information", ".trashes",
    ".spotlight-v100", ".fseventsd", ".temporaryitems",
    ".documentrevisions-v100", "found.000", "lost+found",
}
SKIP_FILES = {
    "thumbs.db", "desktop.ini", ".ds_store", "ehthumbs.db",
    "pagefile.sys", "hiberfil.sys", "swapfile.sys",
}
NOT_ON_TARGET = ("missing", "dup")

# File types, used to label each missing item and to spot app/system files.
CATEGORY_EXT = {
    "Videos": "mp4 mov mkv avi wmv m4v mts m2ts 3gp webm flv mpg mpeg lrv 360 insv vob braw r3d",
    "Photos": "jpg jpeg png heic heif gif bmp tif tiff raw cr2 cr3 nef arw dng orf rw2 raf srw psd webp svg ai xcf",
    "Music": "mp3 m4a aac wav flac ogg wma aiff aif alac opus mid midi",
    "Documents": "pdf doc docx xls xlsx xlsm csv ppt pptx txt md rtf odt ods odp pages numbers key epub mobi tex one msg eml vsdx pub",
    "CAD & 3D": "ipt iam idw ipn dwg dxf step stp igs iges x_t x_b sat sldprt sldasm slddrw stl f3d f3z 3mf obj fbx blend skp prt asm catpart catproduct 3dm max ma mb c4d",
    "Code": "py ipynb js ts tsx jsx c h cpp hpp cs java kt go rs rb php swift m ino sh ps1 bat sql r html css scss vue",
    "Archives": "zip rar 7z tar gz tgz bz2 xz iso dmg img",
}
SYSTEM_EXT = set(
    "dll sys exe msi msp cab cat mui manifest mun pak ocx etl evtx regtrans-ms wim esd pri "
    "so dylib lib a o obj pdb drv efi ax cpl scr tlb winmd nls ttc fon blf "
    "pyc pyd class jar node".split())
SYSTEM_DIR_NAMES = {
    "windows", "winsxs", "system32", "syswow64", "program files", "program files (x86)",
    "programdata", "appdata", "$windows.~bt", "$windows.~ws", "windows.old", "node_modules",
    "site-packages", "__pycache__", ".git", ".svn", "steamapps", "riot games", "epic games",
    "msocache", "$sysreset", "perflogs", "$winreagent",
}
EXT_TO_CAT = {e: c for c, exts in CATEGORY_EXT.items() for e in exts.split()}


class Cancelled(Exception):
    pass


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------

def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_dur(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec} s"
    if sec < 3600:
        return f"{sec // 60} min"
    return f"{sec // 3600} h {sec % 3600 // 60} min"


def now_str():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def norm_root(p):
    p = (p or "").strip().strip('"')
    if IS_WINDOWS and len(p) == 2 and p[1] == ":":
        p += "\\"
    return os.path.abspath(os.path.expanduser(p))


def io_path(root, rel=""):
    r"""Path for real file I/O. On Windows adds the \\?\ prefix so paths over
    260 characters still work."""
    p = os.path.join(root, rel) if rel else root
    if IS_WINDOWS and not p.startswith("\\\\?\\"):
        p = os.path.abspath(p)
        p = "\\\\?\\UNC\\" + p[2:] if p.startswith("\\\\") else "\\\\?\\" + p
    return p


def disp(root, rel=""):
    return os.path.join(root, rel) if rel else root


def nkey(s):
    """Comparison key for names and paths. Case-insensitive like Windows and
    macOS, and Unicode-normalised, because macOS often stores accented names
    in a different (decomposed) form than Windows does."""
    return unicodedata.normalize("NFC", s).lower()


def pkey(rel):
    return nkey(rel)


def bname(rel):
    return nkey(os.path.basename(rel))


def parts(rel):
    return [p for p in rel.split(os.sep) if p] if rel else []


def top_folder(rel):
    p = parts(rel)
    return p[0] if p else ""


def is_inside(a, b):
    a = os.path.normcase(a.rstrip("\\/")) + os.sep
    b = os.path.normcase(b.rstrip("\\/")) + os.sep
    return a.startswith(b)


def short_name(path):
    path = path.rstrip("\\/")
    if IS_WINDOWS and len(path) == 2 and path[1] == ":":
        return path[0].upper()
    return os.path.basename(path) or "root"


def safe_name(s):
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in s) or "source"


def volume_key(root):
    """Identifies a drive by serial number, so cached hashes survive a drive
    getting a different letter next time it is plugged in."""
    try:
        dev = os.stat(root).st_dev
    except OSError:
        dev = 0
    tail = os.path.splitdrive(os.path.abspath(root))[1].rstrip("\\/")
    return f"{dev}|{tail}"


def clean_dest(raw, tgt_root):
    """Validate a destination folder typed by the user. Returns a path relative
    to the target root, or raises ValueError."""
    raw = (raw or "").strip().strip('"')
    if os.path.isabs(raw) or (len(raw) >= 2 and raw[1] == ":"):
        if not is_inside(norm_root(raw), tgt_root):
            raise ValueError("That folder is not on the destination drive.")
        raw = os.path.relpath(norm_root(raw), tgt_root)
        raw = "" if raw == "." else raw
    raw = raw.replace("/", os.sep).replace("\\", os.sep).strip(os.sep)
    if ".." in parts(raw):
        raise ValueError("'..' is not allowed in a destination.")
    return raw


def file_ext(rel):
    return os.path.splitext(rel)[1][1:].lower()


# ----------------------------------------------------------------------------
# Progress shared between the worker thread and whoever displays it
# ----------------------------------------------------------------------------

class Progress:
    def __init__(self, steps):
        self.lock = threading.Lock()
        self.steps = steps
        self.step = 0
        self.t_start = time.time()
        self.d = {}
        self.begin(0)

    def begin(self, step, **kw):
        with self.lock:
            self.step = step
            self.d = {"detail": "", "done": 0, "total": 0, "bytes": 0,
                      "bytes_total": 0, "t0": time.time()}
            self.d.update(kw)

    def set(self, **kw):
        with self.lock:
            self.d.update(kw)

    def add(self, done=0, nbytes=0):
        with self.lock:
            self.d["done"] += done
            self.d["bytes"] += nbytes

    def snap(self):
        with self.lock:
            s = dict(self.d)
            s["step"] = self.step
            s["steps"] = self.steps
        t = time.time()
        s["elapsed"] = t - self.t_start
        s["step_elapsed"] = t - s.pop("t0")
        eta = None
        if s["bytes_total"] and s["bytes"] > 0:
            eta = s["step_elapsed"] * (s["bytes_total"] - s["bytes"]) / s["bytes"]
        elif s["total"] and s["done"] > 0:
            eta = s["step_elapsed"] * (s["total"] - s["done"]) / s["done"]
        s["eta"] = eta
        return s


class ErrorLog:
    def __init__(self, path):
        self.path = path
        self.count = 0
        self.lock = threading.Lock()

    def add(self, stage, path, exc):
        with self.lock:
            self.count += 1
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(f"{now_str()}  [{stage}]  {path}  ->  "
                            f"{type(exc).__name__}: {exc}\n")
            except OSError:
                pass


# ----------------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------------

def scan_tree(root, include_hidden, log, progress, cancel):
    """Walk a drive with os.scandir. On Windows the directory listing already
    carries size and date, so there is no extra call per file."""
    files, dirs = {}, {""}
    stack = [""]
    count = total = 0
    while stack:
        if cancel.is_set():
            raise Cancelled()
        rel_dir = stack.pop()
        try:
            with os.scandir(io_path(root, rel_dir)) as it:
                for entry in it:
                    name = entry.name
                    rel = os.path.join(rel_dir, name) if rel_dir else name
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if include_hidden or name.lower() not in SKIP_DIRS:
                                dirs.add(rel)
                                stack.append(rel)
                        elif entry.is_file(follow_symlinks=False):
                            low = name.lower()
                            if low.endswith(PARTIAL_SUFFIX):
                                continue
                            if not include_hidden and (low in SKIP_FILES or low.startswith("._")):
                                continue
                            st = entry.stat(follow_symlinks=False)
                            files[rel] = (st.st_size, st.st_mtime)
                            count += 1
                            total += st.st_size
                    except OSError as e:
                        log.add("scan", disp(root, rel), e)
        except OSError as e:
            log.add("scan", disp(root, rel_dir), e)
        progress.set(done=count, bytes=total, detail=f"{len(dirs) - 1:,} folders")
    return files, dirs


# ----------------------------------------------------------------------------
# Hashing
# ----------------------------------------------------------------------------

def quick_hash(path, size):
    """Hash of the first and last 64 KB. Returns (quick, full); full is set
    when the file is small enough that the sample covers all of it."""
    h = hashlib.blake2b(digest_size=16)
    with open(path, "rb") as f:
        if size <= SMALL_LIMIT:
            h.update(f.read())
            d = h.hexdigest()
            return d, d
        h.update(f.read(QUICK_SIZE))
        f.seek(size - QUICK_SIZE)
        h.update(f.read(QUICK_SIZE))
        return h.hexdigest(), None


def full_hash(path, cancel=None, on_bytes=None):
    """Whole-file BLAKE2b, streamed through one reusable 1 MB buffer."""
    h = hashlib.blake2b(digest_size=16)
    buf = bytearray(CHUNK_SIZE)
    view = memoryview(buf)
    with open(path, "rb", buffering=0) as f:
        while True:
            n = f.readinto(buf)
            if not n:
                break
            h.update(view[:n])
            if on_bytes:
                on_bytes(n)
            if cancel is not None and cancel.is_set():
                raise Cancelled()
    return h.hexdigest()


class HashCache:
    """SQLite store of hashes. Only the scan thread touches it."""

    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS h (k TEXT PRIMARY KEY, "
                        "size INTEGER, mtime REAL, quick TEXT, full TEXT)")
        self.pending = {}

    def load(self, keys):
        out = {}
        keys = list(keys)
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            q = "SELECT k,size,mtime,quick,full FROM h WHERE k IN (%s)" % ",".join("?" * len(chunk))
            for row in self.db.execute(q, chunk):
                out[row[0]] = row[1:]
        return out

    def put(self, k, size, mtime, quick, full):
        self.pending[k] = (k, size, mtime, quick, full)
        if len(self.pending) >= 5000:
            self.flush()

    def flush(self):
        if self.pending:
            with self.db:
                self.db.executemany("INSERT OR REPLACE INTO h VALUES (?,?,?,?,?)",
                                    list(self.pending.values()))
            self.pending.clear()

    def close(self):
        try:
            self.flush()
            self.db.close()
        except Exception:
            pass


def run_pool(tasks, fn, workers, cancel, on_result):
    """Run fn(task) on a thread pool, feeding tasks gradually so cancelling is
    quick and memory stays flat. on_result runs on the calling thread."""
    it = iter(tasks)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {}

        def fill(n):
            for t in itertools.islice(it, n):
                futs[ex.submit(fn, t)] = t

        fill(workers * 3)
        while futs:
            done, _ = wait(list(futs), timeout=0.5, return_when=FIRST_COMPLETED)
            for f in done:
                t = futs.pop(f)
                try:
                    on_result(t, f.result(), None)
                except Cancelled:
                    pass
                except Exception as e:
                    on_result(t, None, e)
            if cancel.is_set():
                for f in futs:
                    f.cancel()
                break
            fill(len(done))
    if cancel.is_set():
        raise Cancelled()


def interleave(a, b):
    """Alternate tasks from the two drives so both stay busy."""
    out = []
    for x, y in itertools.zip_longest(a, b):
        if x is not None:
            out.append(x)
        if y is not None:
            out.append(y)
    return out


def prefer(rel, candidates):
    """Order target candidates: same path first, then same file name."""
    k, name = pkey(rel), bname(rel)
    return sorted(candidates, key=lambda t: (
        0 if pkey(t) == k else 1 if bname(t) == name else 2, t))


# ----------------------------------------------------------------------------
# The scan job
# ----------------------------------------------------------------------------

SCAN_STEPS = ["Listing the source", "Listing the destination", "Matching by size and date",
              "Comparing content", "Looking for repeats", "Writing the report"]


class ScanJob:
    def __init__(self, src, tgt, label, data_dir, thorough=False,
                 include_hidden=False, cancel=None):
        self.src, self.tgt = norm_root(src), norm_root(tgt)
        self.label = (label or "").strip() or short_name(self.src)
        self.data_dir = os.path.abspath(data_dir)
        self.thorough = thorough
        self.include_hidden = include_hidden
        self.cancel = cancel or threading.Event()
        self.progress = Progress(SCAN_STEPS)
        self.plan = None
        self.run_dir = None
        self.opened = 0

    def validate(self):
        for p, name in ((self.src, "The source"), (self.tgt, "The destination")):
            if not os.path.isdir(p):
                raise ValueError(f"{name} is not a folder or is not connected: {p}")
        if is_inside(self.src, self.tgt) or is_inside(self.tgt, self.src):
            raise ValueError("The source and destination must not be the same place or inside each other.")

    def run(self):
        self.validate()
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.run_dir = os.path.join(
            self.data_dir, "scans",
            f"{stamp}_{safe_name(self.label)}_to_{safe_name(short_name(self.tgt))}")
        os.makedirs(self.run_dir, exist_ok=True)
        self.log = ErrorLog(os.path.join(self.run_dir, "errors.log"))
        self.cache = HashCache(os.path.join(self.data_dir, "hash_cache.sqlite"))
        self.vk = {"s": volume_key(self.src), "t": volume_key(self.tgt)}
        self.roots = {"s": self.src, "t": self.tgt}
        t0 = time.time()
        try:
            self.progress.begin(0)
            self.src_files, self.src_dirs = scan_tree(
                self.src, self.include_hidden, self.log, self.progress, self.cancel)
            self.progress.begin(1)
            self.tgt_files, self.tgt_dirs = scan_tree(
                self.tgt, self.include_hidden, self.log, self.progress, self.cancel)
            self.status = {}
            self.meta_cands = {}
            self.hashes = {}
            remaining = self.match_metadata()
            self.match_content(remaining)
            self.find_repeats()
        finally:
            self.cache.close()
        self.progress.begin(5)
        summary = summarise(self.src_files, self.src_dirs, self.tgt_files, self.tgt_dirs, self.status)
        summary["totals"]["files_opened"] = self.opened
        self.plan = {
            "app": "stragglers", "version": 3, "created": now_str(),
            "source_root": self.src, "target_root": self.tgt, "source_label": self.label,
            "mode": "thorough" if self.thorough else "fast",
            "elapsed": time.time() - t0, "errors": self.log.count,
        }
        self.plan.update(summary)
        write_reports(self.run_dir, self.plan)
        return self.plan

    # -- stage 2: size + date ------------------------------------------------
    def match_metadata(self):
        self.progress.begin(2)
        src_files, tgt_files = self.src_files, self.tgt_files
        tgt_sizes = set()
        by_size_time = defaultdict(list)
        for t, (s, m) in tgt_files.items():
            if s > 0:
                tgt_sizes.add(s)
                by_size_time[(s, int(round(m)))].append(t)
        tgt_empty = {bname(r) for r, (s, _) in tgt_files.items() if s == 0}

        candidates = []
        for rel, (s, _) in src_files.items():
            if s == 0:
                present = bname(rel) in tgt_empty
                self.status[rel] = {"state": "present", "how": "name"} if present else {"state": "missing"}
            elif s not in tgt_sizes:
                self.status[rel] = {"state": "missing"}
            else:
                candidates.append(rel)
        self.progress.set(total=len(candidates))
        if self.cancel.is_set():
            raise Cancelled()

        remaining = []
        for i, rel in enumerate(candidates):
            s, m = src_files[rel]
            sec = int(round(m))
            name = bname(rel)
            k = pkey(rel)
            best, score, others = None, 9, []
            for d in (0, -1, 1, -2, 2):
                for t in by_size_time.get((s, sec + d), ()):
                    if abs(tgt_files[t][1] - m) > 2.0:
                        continue
                    sc = 0 if pkey(t) == k else 1 if bname(t) == name else 2
                    if sc == 2:
                        others.append(t)
                    if sc < score:
                        best, score = t, sc
                if score == 0:
                    break
            if best is not None and (score < 2 or s >= META_ANYNAME_MIN):
                self.status[rel] = {"state": "present", "match": best, "how": "meta"}
            else:
                if others:      # same size and date, different name: confirm by content
                    self.meta_cands[rel] = others[:20]
                remaining.append(rel)
            if i % 5000 == 0:
                self.progress.set(done=i)
        del by_size_time

        # FAT and exFAT drives can shift dates by whole hours (time zones,
        # daylight saving). Accept those only for files with the same name.
        if remaining:
            need = {src_files[r][0] for r in remaining}
            by_size_name = defaultdict(list)
            for t, (s, m) in tgt_files.items():
                if s in need:
                    by_size_name[(s, bname(t))].append(t)
            still = []
            for rel in remaining:
                s, m = src_files[rel]
                hit = None
                for t in by_size_name.get((s, bname(rel)), ()):
                    diff = tgt_files[t][1] - m
                    hours = round(diff / 3600)
                    if 1 <= abs(hours) <= 14 and abs(diff - hours * 3600) <= 2.0:
                        hit = t
                        break
                if hit:
                    self.status[rel] = {"state": "present", "match": hit, "how": "meta"}
                else:
                    still.append(rel)
            remaining = still
        self.progress.set(done=len(candidates),
                          detail=f"{len(candidates) - len(remaining):,} matched without reading")
        return remaining

    # -- hashing helper -----------------------------------------------------
    def _ensure(self, side_rels, kind, workers):
        """Make sure each (side, rel) has a quick or full hash, from the cache
        if possible and from the thread pool otherwise."""
        files = {"s": self.src_files, "t": self.tgt_files}
        keys = {sr: f"{self.vk[sr[0]]}|{sr[1]}" for sr in side_rels}
        cached = self.cache.load(keys.values())
        todo = {"s": [], "t": []}
        for sr in side_rels:
            side, rel = sr
            s, m = files[side][rel]
            h = self.hashes.setdefault(sr, [None, None])
            row = cached.get(keys[sr])
            if row and row[0] == s and abs(row[1] - m) < 1e-6:
                h[0] = h[0] or row[2]
                h[1] = h[1] or row[3]
            if (kind == "quick" and not h[0]) or (kind == "full" and not h[1]):
                todo[side].append(rel)
        tasks = interleave([("s", r) for r in sorted(todo["s"])],
                           [("t", r) for r in sorted(todo["t"])])
        if kind == "quick":
            total_b = sum(min(files[sd][r][0], SMALL_LIMIT) for sd, r in tasks)
        else:
            total_b = sum(files[sd][r][0] for sd, r in tasks)
        self.progress.set(total=len(tasks), done=0, bytes=0, bytes_total=total_b)

        def work(task):
            side, rel = task
            path = io_path(self.roots[side], rel)
            size = files[side][rel][0]
            if kind == "quick":
                r = quick_hash(path, size)
                self.progress.add(nbytes=min(size, SMALL_LIMIT))
                return r
            return full_hash(path, self.cancel, lambda n: self.progress.add(nbytes=n))

        def done(task, result, err):
            self.progress.add(done=1)
            self.opened += 1
            side, rel = task
            if err is not None:
                self.log.add("read", disp(self.roots[side], rel), err)
                self.hashes[task] = ["!error", "!error"]
                return
            h = self.hashes[task]
            if kind == "quick":
                h[0], h[1] = result[0], (result[1] or h[1])
            else:
                h[1] = result
            s, m = files[side][rel]
            self.cache.put(keys[task], s, m, h[0], h[1])

        run_pool(tasks, work, workers, self.cancel, done)
        self.cache.flush()

    # -- stage 3: content ----------------------------------------------------
    def match_content(self, remaining):
        self.progress.begin(3)
        if not remaining:
            return
        src_files, tgt_files = self.src_files, self.tgt_files
        sizes_any = set()          # sizes where every same-size target is a candidate
        size_names = set()         # (size, name) pairs for fast mode
        for rel in remaining:
            s = src_files[rel][0]
            if self.thorough or s >= BIG_FILE:
                sizes_any.add(s)
            else:
                size_names.add((s, bname(rel)))
        extra = set()
        for rel in remaining:
            extra.update(self.meta_cands.get(rel, ()))
        tgt_need, found_pairs = [], set()
        for t, (s, _) in tgt_files.items():
            if s in sizes_any or t in extra:
                tgt_need.append(t)
            elif size_names:
                pair = (s, bname(t))
                if pair in size_names:
                    tgt_need.append(t)
                    found_pairs.add(pair)

        # Fast mode: a small file with no same-size, same-name (or same-date)
        # file on the destination is missing. No need to read it.
        still = []
        for rel in remaining:
            s = src_files[rel][0]
            if (self.thorough or s >= BIG_FILE
                    or (s, bname(rel)) in found_pairs
                    or rel in self.meta_cands):
                still.append(rel)
            else:
                self.status[rel] = {"state": "missing"}
        remaining = still
        if not remaining:
            return
        self.progress.set(detail=f"{len(remaining):,} source and {len(tgt_need):,} destination files to read")
        self._ensure([("s", r) for r in remaining] + [("t", t) for t in tgt_need], "quick", QUICK_WORKERS)

        index = defaultdict(list)
        for t in tgt_need:
            q = self.hashes[("t", t)][0]
            if q and q != "!error":
                index[(tgt_files[t][0], q)].append(t)

        need_full, pending = set(), {}
        for rel in remaining:
            s = src_files[rel][0]
            q = self.hashes[("s", rel)][0]
            if q == "!error":
                self.status[rel] = {"state": "error"}
                continue
            same = index.get((s, q), [])
            if not self.thorough and s < BIG_FILE:
                name = bname(rel)
                mc = set(self.meta_cands.get(rel, ()))
                same = [t for t in same if bname(t) == name or t in mc]
            if not same:
                self.status[rel] = {"state": "missing"}
            elif s <= SMALL_LIMIT:
                self.status[rel] = {"state": "present", "match": prefer(rel, same)[0], "how": "content"}
            else:
                pending[rel] = same
                need_full.add(("s", rel))
                need_full.update(("t", t) for t in same)

        if pending:
            self.progress.set(detail=f"confirming {len(pending):,} large files byte for byte")
            self._ensure(sorted(need_full), "full", FULL_WORKERS)
            for rel, same in pending.items():
                f = self.hashes[("s", rel)][1]
                if f == "!error":
                    self.status[rel] = {"state": "error"}
                    continue
                match = next((t for t in prefer(rel, same) if self.hashes[("t", t)][1] == f), None)
                self.status[rel] = ({"state": "present", "match": match, "how": "content"}
                                    if match else {"state": "missing"})

    # -- stage 4: repeats inside the source -----------------------------------
    def find_repeats(self):
        self.progress.begin(4)
        groups = defaultdict(list)
        for rel, st in self.status.items():
            s = self.src_files[rel][0]
            if st["state"] == "missing" and s > 0:
                groups[s].append(rel)
        cand = [r for rels in groups.values() if len(rels) > 1 for r in rels]
        if not cand:
            return
        self._ensure([("s", r) for r in cand], "quick", QUICK_WORKERS)
        # The copy kept as the original is the one in the fuller folder, so a
        # stray "copy of" folder is what gets treated as the repeat.
        per_dir = Counter(os.path.dirname(r) for r in self.src_files)
        buckets = defaultdict(list)
        for r in sorted(cand, key=lambda r: (-per_dir[os.path.dirname(r)], r)):
            q = self.hashes[("s", r)][0]
            if q and q != "!error":
                buckets[(self.src_files[r][0], q)].append(r)
        multi = [b for b in buckets.values() if len(b) > 1]
        big = [("s", r) for b in multi for r in b if self.src_files[r][0] > SMALL_LIMIT]
        if big:
            self._ensure(big, "full", FULL_WORKERS)
        for b in multi:
            seen = {}
            for r in b:
                f = self.hashes[("s", r)][1]
                if not f or f == "!error":
                    continue
                if f in seen:
                    self.status[r] = {"state": "dup", "match": seen[f]}
                else:
                    seen[f] = r


# ----------------------------------------------------------------------------
# Turning per-file results into reviewable items
# ----------------------------------------------------------------------------

def build_tree(src_files, src_dirs, status):
    children, direct = defaultdict(list), defaultdict(list)
    for d in src_dirs:
        if d:
            children[os.path.dirname(d)].append(d)
    for rel in src_files:
        direct[os.path.dirname(rel)].append(rel)
    stats = defaultdict(Counter)
    for rel, (size, _) in src_files.items():
        state = status[rel]["state"]
        d = os.path.dirname(rel)
        while True:
            s = stats[d]
            s["files"] += 1
            s["bytes"] += size
            if state in NOT_ON_TARGET:
                s["nt"] += 1
            if state == "error":
                s["err"] += 1
            if not d:
                break
            d = os.path.dirname(d)
    return children, direct, stats


def build_location_votes(status):
    """Learn where each source folder's content lives on the destination. A file
    at A/B/x.jpg found at Old/A/B/x.jpg votes that 'A' lives at 'Old/A'."""
    votes = defaultdict(Counter)
    for rel, st in status.items():
        m = st.get("match")
        if st["state"] != "present" or not m:
            continue
        sp, tp = parts(os.path.dirname(rel)), parts(os.path.dirname(m))
        spl, tpl = [nkey(p) for p in sp], [nkey(p) for p in tp]
        for k in range(len(sp), -1, -1):
            sub = spl[k:]
            if len(sub) > len(tpl):
                break
            if sub and tpl[len(tpl) - len(sub):] != sub:
                break
            votes[os.sep.join(sp[:k])][os.sep.join(tp[:len(tp) - len(sub)])] += 1
    return votes


def make_blocks(children, direct, stats, status):
    """A wholly missing folder becomes one 'folder' item; otherwise the missing
    files directly inside a folder become one 'files' item."""
    blocks = []

    def files_under(d):
        out, stack = [], [d]
        while stack:
            x = stack.pop()
            out.extend(direct.get(x, []))
            stack.extend(children.get(x, []))
        return sorted(out)

    stack = [""]
    order = []
    while stack:                       # iterative, so very deep trees are fine
        d = stack.pop()
        s = stats.get(d)
        if not s or s["nt"] == 0:
            continue
        if d and s["nt"] == s["files"]:
            order.append(("folder", d, files_under(d)))
            continue
        loose = sorted(f for f in direct.get(d, []) if status[f]["state"] in NOT_ON_TARGET)
        if loose:
            order.append(("files", d, loose))
        for c in sorted(children.get(d, []), key=str.lower, reverse=True):
            stack.append(c)
    for kind, d, files in order:
        blocks.append({"kind": kind, "src": d, "files": files})
    return blocks


def suggest_destination(block, votes, stats, tgt_dir_keys, tgt_dirs_by_name):
    """Pick the closest existing place on the destination, or keep the source
    path when nothing convincing is found."""
    d = block["src"]
    if d and pkey(d) in tgt_dir_keys:
        return d, "the same folder already exists on the destination"

    def below(a):
        return d[len(a):].lstrip(os.sep) if a else d

    # Nearest ancestor whose files were clearly found in one place. A mapping
    # to the very top of the destination is ignored: it usually means the
    # folder was flattened, and keeping the source path is the safer choice.
    a = d if block["kind"] == "files" else os.path.dirname(d)
    while a:
        if a in votes:
            loc, n = votes[a].most_common(1)[0]
            present = stats[a]["files"] - stats[a]["nt"]
            if loc and n >= 3 and n * 2 >= present:
                return (os.path.join(loc, below(a)) if below(a) else loc,
                        f"{n:,} files from '{a}' are already in '{loc}'")
        a = os.path.dirname(a)

    name = bname(d)
    if name and name in tgt_dirs_by_name:
        cands = tgt_dirs_by_name[name]
        parent = bname(os.path.dirname(d))
        cands = sorted(cands, key=lambda c: (
            0 if bname(os.path.dirname(c)) == parent else 1, len(c)))
        extra = f" ({len(cands) - 1} others share the name)" if len(cands) > 1 else ""
        return cands[0], f"a folder with the same name is already on the destination{extra}"

    return d, "nothing related on the destination, so it keeps its own path"


def classify(files_with_sizes, src_path):
    """Label an item by what most of its bytes are, and flag items that look
    like installed apps or operating system files."""
    by_cat = Counter()
    sys_count = 0
    for rel, size in files_with_sizes:
        e = file_ext(rel)
        by_cat[EXT_TO_CAT.get(e, "Other")] += size or 1
        if e in SYSTEM_EXT:
            sys_count += 1
    n = max(1, len(files_with_sizes))
    path_parts = {p.lower() for p in parts(src_path)}
    system = bool(path_parts & SYSTEM_DIR_NAMES) or sys_count / n >= 0.5
    if system:
        return "Apps & system", True
    cat = by_cat.most_common(1)[0][0] if by_cat else "Other"
    return cat, False


def summarise(src_files, src_dirs, tgt_files, tgt_dirs, status):
    children, direct, stats = build_tree(src_files, src_dirs, status)
    votes = build_location_votes(status)
    tgt_dir_keys = {pkey(d) for d in tgt_dirs}
    tgt_dirs_by_name = defaultdict(list)
    for d in tgt_dirs:
        if d:
            tgt_dirs_by_name[bname(d)].append(d)

    raw = make_blocks(children, direct, stats, status)
    owner = {}
    for i, b in enumerate(raw, 1):
        for rel in b["files"]:
            owner[rel] = i

    blocks = []
    for i, b in enumerate(raw, 1):
        dest, reason = suggest_destination(b, votes, stats, tgt_dir_keys, tgt_dirs_by_name)
        files = [[rel, src_files[rel][0]] for rel in b["files"]]
        repeats = defaultdict(lambda: [0, 0])     # block id of the original -> [count, bytes]
        dup_files = {}
        for rel, size in files:
            st = status[rel]
            if st["state"] == "dup":
                ob = owner.get(st["match"], 0)
                repeats[ob][0] += 1
                repeats[ob][1] += size
                dup_files[rel] = st["match"]
        category, system = classify(files, b["src"])
        total_b = sum(s for _, s in files)
        rep_b = sum(v[1] for v in repeats.values())
        block = {
            "id": i, "kind": b["kind"], "src": b["src"], "top": top_folder(b["src"]),
            "count": len(files), "bytes": total_b,
            "category": category, "system": system,
            "repeats": {str(k): v for k, v in repeats.items()},
            "repeat_count": len(dup_files), "repeat_bytes": rep_b,
            "all_repeats": bool(files) and len(dup_files) == len(files),
            "exists_on_target": bool(b["src"]) and pkey(b["src"]) in tgt_dir_keys,
            "suggested_dest": dest, "reason": reason,
            "files": files, "dup_files": dup_files,
        }
        if block["all_repeats"]:
            where = Counter(os.path.dirname(m) for m in dup_files.values())
            block["repeat_of"] = where.most_common(1)[0][0]
        if b["kind"] == "files":
            block["folder_total"] = len(direct.get(b["src"], []))
            block["folder_present"] = sum(
                1 for f in direct.get(b["src"], []) if status[f]["state"] == "present")
        blocks.append(block)

    totals = Counter()
    for rel, (size, _) in src_files.items():
        st = status[rel]
        state = st["state"]
        if state == "present":
            m = st.get("match")
            cat = "same" if (m is None or pkey(m) == pkey(rel)) else "moved"
            totals[st.get("how", "content") + "_n"] += 1
        else:
            cat = state
        totals[cat + "_n"] += 1
        totals[cat + "_b"] += size
        totals["total_n"] += 1
        totals["total_b"] += size
    totals["target_n"] = len(tgt_files)

    categories = defaultdict(lambda: {"items": 0, "files": 0, "bytes": 0, "unique_bytes": 0})
    for b in blocks:
        c = categories[b["category"]]
        c["items"] += 1
        c["files"] += b["count"]
        c["bytes"] += b["bytes"]
        c["unique_bytes"] += b["bytes"] - b["repeat_bytes"]

    relocated = []

    stack = [""]
    while stack:
        d = stack.pop()
        s = stats.get(d)
        if not s or s["files"] == 0:
            continue
        if d and s["nt"] == 0 and s["err"] == 0:
            if pkey(d) not in tgt_dir_keys:
                loc = votes[d].most_common(1)[0][0] if votes.get(d) else None
                relocated.append({"src": d, "files": s["files"], "bytes": s["bytes"], "found_at": loc})
            continue
        stack.extend(children.get(d, []))
    relocated.sort(key=lambda x: -x["bytes"])

    return {"totals": dict(totals), "categories": dict(categories),
            "relocated": relocated, "blocks": blocks}


def dest_file(block, dest_dir, rel):
    if block["kind"] == "folder":
        inner = rel[len(block["src"]):].lstrip(os.sep)
    else:
        inner = os.path.basename(rel)
    return os.path.join(dest_dir, inner)


# ----------------------------------------------------------------------------
# Reports
# ----------------------------------------------------------------------------

def write_reports(run_dir, plan):
    blocks, t = plan["blocks"], Counter(plan["totals"])
    src, tgt = plan["source_root"], plan["target_root"]

    with open(os.path.join(run_dir, "plan.json"), "w", encoding="utf-8") as f:
        json.dump(plan, f)
    meta = {k: plan[k] for k in ("created", "source_root", "target_root", "source_label", "mode")}
    meta["items"] = len(blocks)
    meta["missing_b"] = t["missing_b"]
    with open(os.path.join(run_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)

    with open(os.path.join(run_dir, "missing_files.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item", "type", "looks_like_apps_or_system", "source_file", "size_bytes",
                    "size", "repeat_of", "suggested_destination_file"])
        for b in blocks:
            for rel, size in b["files"]:
                w.writerow([b["id"], b["category"], "yes" if b["system"] else "", disp(src, rel),
                            size, human(size), b["dup_files"].get(rel, ""),
                            disp(tgt, dest_file(b, b["suggested_dest"], rel))])

    user_blocks = [b for b in blocks if not b["system"]]
    sys_blocks = [b for b in blocks if b["system"]]
    L = [f"# What `{src}` has that `{tgt}` does not\n",
         f"Scanned {plan['created']} in {fmt_dur(plan.get('elapsed', 0))} ({plan['mode']} mode). "
         f"A file counts as already there even if it sits in another folder or has another name.\n",
         "## In short\n",
         "| | Files | Size |", "|---|---:|---:|"]
    for title, k in [("Scanned on the source", "total"),
                     ("Already on the destination, same folder", "same"),
                     ("Already on the destination, another folder", "moved"),
                     ("**Missing from the destination**", "missing"),
                     ("Repeats of missing files (copied once)", "dup"),
                     ("Could not be read", "error")]:
        L.append(f"| {title} | {t[k + '_n']:,} | {human(t[k + '_b'])} |")
    L.append("")
    if sys_blocks:
        sb = sum(b["bytes"] for b in sys_blocks)
        L.append(f"{human(sb)} of the missing data looks like installed apps or operating system "
                 f"files. Those items are listed separately at the end and are not selected by default.\n")

    if blocks:
        L.append("## By type\n\n| Type | Items | Files | Size (repeats removed) |\n|---|---:|---:|---:|")
        for cat, c in sorted(plan["categories"].items(), key=lambda kv: -kv[1]["unique_bytes"]):
            L.append(f"| {cat} | {c['items']:,} | {c['files']:,} | {human(c['unique_bytes'])} |")
        L.append("")

    groups = defaultdict(list)
    for b in user_blocks:
        groups[b["top"] or "(top level)"].append(b)
    if groups:
        L.append("## By folder\n")
        L.append("Whole folders are one line each. Every file is listed in `missing_files.csv`.\n")
        order = sorted(groups.items(), key=lambda kv: -sum(b["bytes"] for b in kv[1]))
        for g, bl in order:
            gb = sum(b["bytes"] for b in bl)
            gf = sum(b["count"] for b in bl)
            L.append(f"### {g}  ({human(gb)}, {gf:,} files)\n")
            bl = sorted(bl, key=lambda b: -b["bytes"])
            for b in bl[:MAX_REPORT_ITEMS_PER_GROUP]:
                where = f"`{b['suggested_dest'] or '(top level)'}`"
                if b["kind"] == "folder":
                    what = ("folder exists there but has none of these" if b["exists_on_target"]
                            else "whole folder")
                    line = f"- `{b['src']}`: {what}, {b['count']:,} files, {human(b['bytes'])}. Goes to {where}"
                else:
                    line = (f"- `{b['src'] or '(top level)'}`: {b['count']:,} of {b['folder_total']:,} "
                            f"files missing, {human(b['bytes'])}. Goes to {where}")
                if b["all_repeats"]:
                    line += f". Same files as `{b['repeat_of']}`"
                elif b["repeat_bytes"]:
                    line += f". Includes {human(b['repeat_bytes'])} of repeats"
                L.append(line)
                if b["kind"] == "files" and b["count"] <= 5:
                    for rel, size in b["files"]:
                        L.append(f"  - {os.path.basename(rel)} ({human(size)})")
            if len(bl) > MAX_REPORT_ITEMS_PER_GROUP:
                rest = bl[MAX_REPORT_ITEMS_PER_GROUP:]
                L.append(f"- and {len(rest):,} smaller items, {human(sum(b['bytes'] for b in rest))} in total")
            L.append("")

    if sys_blocks:
        L.append("## Looks like apps or system files\n")
        L.append("| Folder | Items | Files | Size |\n|---|---:|---:|---:|")
        agg = defaultdict(lambda: [0, 0, 0])
        for b in sys_blocks:
            k = os.sep.join(parts(b["src"])[:2]) or "(top level)"
            a = agg[k]
            a[0] += 1
            a[1] += b["count"]
            a[2] += b["bytes"]
        for k, a in sorted(agg.items(), key=lambda kv: -kv[1][2])[:40]:
            L.append(f"| `{k}` | {a[0]:,} | {a[1]:,} | {human(a[2])} |")
        L.append("")

    if not blocks:
        L.append("## Nothing is missing\n")

    if plan["relocated"]:
        L.append("## Already there, in another folder\n")
        L.append("| Source folder | Files | Size | Found at |\n|---|---:|---:|---|")
        for r in plan["relocated"][:30]:
            at = f"`{r['found_at']}`" if r["found_at"] is not None else "spread across several folders"
            L.append(f"| `{r['src']}` | {r['files']:,} | {human(r['bytes'])} | {at} |")
        L.append("")
    L.append(f"## Problems\n\n{plan['errors']:,} problems logged."
             + (" See errors.log." if plan["errors"] else "") + "\n")
    with open(os.path.join(run_dir, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))


# ----------------------------------------------------------------------------
# Copying
# ----------------------------------------------------------------------------

def copy_one(src_root, rel, size, tgt_root, dst_rel, label, verify, cancel, on_bytes):
    """Copy one file without ever overwriting anything. It is written under a
    temporary name and renamed when complete, so an interruption never leaves
    a half-written file behind."""
    src = io_path(src_root, rel)
    if os.stat(src).st_size != size:
        raise OSError("the source file changed since the scan")
    dst = io_path(tgt_root, dst_rel)
    if os.path.exists(dst):
        if (os.path.isfile(dst) and os.path.getsize(dst) == size
                and full_hash(dst) == full_hash(src)):
            on_bytes(size)
            return "already there", dst_rel
        base, ext = os.path.splitext(dst_rel)
        n = 1
        while True:
            cand = f"{base} (from {label}){ext}" if n == 1 else f"{base} (from {label} {n}){ext}"
            if not os.path.exists(io_path(tgt_root, cand)):
                dst_rel, dst = cand, io_path(tgt_root, cand)
                break
            n += 1

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + PARTIAL_SUFFIX
    h = hashlib.blake2b(digest_size=16) if verify else None
    try:
        buf = bytearray(COPY_CHUNK)
        view = memoryview(buf)
        with open(src, "rb", buffering=0) as fi, open(tmp, "wb") as fo:
            while True:
                n = fi.readinto(buf)
                if not n:
                    break
                fo.write(view[:n])
                if h:
                    h.update(view[:n])
                on_bytes(n)
                if cancel.is_set():
                    raise Cancelled()
        try:
            shutil.copystat(src, tmp)
        except OSError:
            pass
        if os.path.getsize(tmp) != size:
            raise OSError("size mismatch after copying")
        if h and full_hash(tmp) != h.hexdigest():
            raise OSError("content mismatch after copying")
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return "copied", dst_rel


class CopyJob:
    def __init__(self, plan, decisions, run_dir, verify=False, skip_repeats=True, cancel=None):
        self.plan = plan
        self.decisions = decisions          # list of (block, dest_rel)
        self.run_dir = run_dir
        self.verify = verify
        self.skip_repeats = skip_repeats
        self.cancel = cancel or threading.Event()
        self.progress = Progress(["Copying"])
        self.counts = Counter()
        self.stopped_reason = None
        self.log_path = os.path.join(run_dir, "copy_log.csv")

    def jobs(self):
        """(rel, size, dest_rel) for every file to copy. A repeat is skipped
        when the file it repeats is also being copied."""
        chosen = set()
        for b, _ in self.decisions:
            chosen.update(rel for rel, _ in b["files"])
        out, skipped = [], []
        for b, dest in self.decisions:
            dups = b.get("dup_files", {})
            for rel, size in b["files"]:
                if self.skip_repeats and dups.get(rel) in chosen:
                    skipped.append((rel, size, dups[rel]))
                    continue
                out.append((rel, size, dest_file(b, dest, rel)))
        return out, skipped

    def run(self):
        src_root, tgt_root = self.plan["source_root"], self.plan["target_root"]
        label = self.plan["source_label"]
        jobs, skipped = self.jobs()
        log = ErrorLog(os.path.join(self.run_dir, "errors.log"))
        self.counts["repeat skipped"] = len(skipped)
        self.progress.begin(0, total=len(jobs), bytes_total=sum(s for _, s, _ in jobs))
        new_file = not os.path.exists(self.log_path)
        with open(self.log_path, "a", encoding="utf-8-sig", newline="") as jf:
            w = csv.writer(jf)
            if new_file:
                w.writerow(["time", "result", "source", "destination", "bytes", "note"])
            for rel, size, orig in skipped:
                w.writerow([now_str(), "repeat skipped", disp(src_root, rel), "", size,
                            f"same as {disp(src_root, orig)}"])
            for rel, size, dst_rel in jobs:
                if self.cancel.is_set():
                    self.stopped_reason = "You stopped the copy."
                    break
                self.progress.set(detail=rel)
                before = self.progress.snap()["bytes"]
                try:
                    result, final = copy_one(src_root, rel, size, tgt_root, dst_rel, label,
                                             self.verify, self.cancel,
                                             lambda n: self.progress.add(nbytes=n))
                    self.counts[result] += 1
                    note = "renamed to avoid overwriting" if final != dst_rel else ""
                    w.writerow([now_str(), result, disp(src_root, rel), disp(tgt_root, final), size, note])
                except Cancelled:
                    self.stopped_reason = "You stopped the copy. The file in progress was removed."
                    break
                except OSError as e:
                    self.counts["failed"] += 1
                    log.add("copy", disp(src_root, rel), e)
                    w.writerow([now_str(), "failed", disp(src_root, rel), disp(tgt_root, dst_rel), size, str(e)])
                    self.progress.add(nbytes=max(0, size - (self.progress.snap()["bytes"] - before)))
                    if not os.path.isdir(src_root) or not os.path.isdir(tgt_root):
                        self.stopped_reason = ("A drive seems to be disconnected. Reconnect it and copy "
                                               "again: files already copied are recognised and skipped.")
                        break
                    if getattr(e, "errno", None) == 28:
                        self.stopped_reason = "The destination drive is full."
                        break
                self.progress.add(done=1)
                jf.flush()
        return self.counts


def default_data_dir():
    """Where scans and the hash cache live: next to the user's documents,
    not inside the program folder."""
    base = os.environ.get("STRAGGLERS_HOME")
    if base:
        return base
    if IS_WINDOWS:
        root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(root, "stragglers")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/stragglers")
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
                        "stragglers")
