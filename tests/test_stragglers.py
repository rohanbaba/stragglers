"""End-to-end tests on small throwaway drives. Standard library only:

    python -m unittest discover -s tests -v
"""

import os
import shutil
import tempfile
import threading
import unittest

from stragglers.engine import CopyJob, ScanJob, clean_dest

T = 1_650_000_000  # a fixed modified time


def write(root, rel, data, mtime=None):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    if mtime is not None:
        os.utime(p, (mtime, mtime))


def blob(seed, size):
    """Deterministic bytes that differ per seed."""
    out = bytearray()
    x = seed * 2654435761 % 2**32 or 1
    while len(out) < size:
        x = (x * 1103515245 + 12345) % 2**31
        out += x.to_bytes(4, "little")
    return bytes(out[:size])


def make_drives(base):
    src, tgt = os.path.join(base, "src"), os.path.join(base, "tgt")
    a, b = blob(1, 300_000), blob(2, 300_000)
    write(tgt, "Archive/Projects/Alpha/a.bin", a, T)          # moved, same date
    write(src, "Projects/Alpha/a.bin", a, T)
    write(tgt, "Archive/Projects/Alpha/b.bin", b, T + 5)      # moved, date changed
    write(src, "Projects/Alpha/b.bin", b, T + 999)
    for i in range(4):                                         # moved, same dates
        d = blob(10 + i, 5000)
        write(tgt, f"Archive/Projects/Beta/x{i}.txt", d, T + i)
        write(src, f"Projects/Beta/x{i}.txt", d, T + i)
    write(src, "Projects/Beta/new.txt", b"brand new")         # missing, folder partly there
    write(src, "Projects/Gamma/g1.dat", blob(3, 300_000))     # whole folder missing
    write(src, "Projects/Gamma/sub/g2.dat", blob(4, 5000))
    c = blob(5, 500_000)
    write(tgt, "Docs/report.pdf", c, T)                       # one-hour clock shift
    write(src, "Docs/report.pdf", c, T + 3600)
    write(tgt, "Docs/notes.txt", b"old notes", T)              # same name, different file
    write(src, "Docs/notes.txt", b"new notes!", T)
    d = blob(6, 200_000)
    write(tgt, "Music/song_renamed.mp3", d, T)                # renamed, same date
    write(src, "Music/song.mp3", d, T)
    e = blob(7, 1000)
    write(src, "Photos/2019/Beach/p1.jpg", e)                 # missing twice: a repeat
    write(src, "Backup/Beach copy/p1.jpg", e)
    x = bytearray(blob(8, 400_000))
    y = bytearray(x)
    y[200_000] ^= 0xFF
    write(tgt, "Video/clip.mov", bytes(x), T)                 # same size and name, different content
    write(src, "Video/clip.mov", bytes(y), T + 50)
    big = blob(9, 3_000_000)
    write(tgt, "Big/movie.mp4", big, T)                       # large, renamed and re-dated
    write(src, "Clips/movie_copy.mp4", big, T + 77)
    write(src, "Old PC/Windows/System32/a.dll", blob(11, 4000))   # looks like system files
    write(src, "Old PC/Windows/System32/b.dll", blob(12, 4000))
    write(src, "Thumbs.db", b"junk")                          # ignored
    return src, tgt


class StragglersTest(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="stragglers-test-")
        self.src, self.tgt = make_drives(self.base)
        self.data = os.path.join(self.base, "data")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def scan(self, **kw):
        job = ScanJob(self.src, self.tgt, "Old drive", self.data, **kw)
        return job, job.run()

    def by_src(self, plan):
        return {b["src"].replace(os.sep, "/"): b for b in plan["blocks"]}

    def test_finds_exactly_what_is_missing(self):
        _, plan = self.scan()
        items = self.by_src(plan)
        self.assertEqual(set(items), {
            "Projects/Beta", "Projects/Gamma", "Docs", "Photos", "Backup", "Video", "Old PC"})
        self.assertEqual(items["Projects/Gamma"]["kind"], "folder")
        self.assertEqual(items["Projects/Beta"]["kind"], "files")
        self.assertEqual(items["Projects/Beta"]["count"], 1)
        t = plan["totals"]
        self.assertEqual(t["dup_n"], 1)
        self.assertEqual(t["error_n"] if "error_n" in t else 0, 0)

    def test_moved_folder_suggests_its_new_home(self):
        _, plan = self.scan()
        items = self.by_src(plan)
        self.assertEqual(items["Projects/Gamma"]["suggested_dest"].replace(os.sep, "/"),
                         "Archive/Projects/Gamma")
        self.assertEqual(items["Projects/Beta"]["suggested_dest"].replace(os.sep, "/"),
                         "Archive/Projects/Beta")

    def test_system_files_are_flagged(self):
        _, plan = self.scan()
        items = self.by_src(plan)
        self.assertTrue(items["Old PC"]["system"])
        self.assertFalse(items["Projects/Gamma"]["system"])

    def test_thorough_mode_agrees(self):
        _, fast = self.scan()
        _, thorough = self.scan(thorough=True)
        self.assertEqual(fast["totals"]["missing_n"], thorough["totals"]["missing_n"])

    def test_copy_then_rescan_finds_nothing(self):
        job, plan = self.scan()
        decisions = [(b, b["suggested_dest"]) for b in plan["blocks"]]
        cj = CopyJob(plan, decisions, job.run_dir, verify=True)
        counts = cj.run()
        self.assertEqual(counts["failed"], 0)
        self.assertEqual(counts["repeat skipped"], 1)
        # nothing on the destination was overwritten
        with open(os.path.join(self.tgt, "Docs", "notes.txt"), "rb") as f:
            self.assertEqual(f.read(), b"old notes")
        self.assertTrue(os.path.exists(os.path.join(self.tgt, "Docs", "notes (from Old drive).txt")))
        _, again = self.scan()
        self.assertEqual(again["totals"].get("missing_n", 0), 0)
        leftovers = [f for _, _, fs in os.walk(self.tgt) for f in fs if f.endswith(".stragglers-part")]
        self.assertEqual(leftovers, [])

    def test_cancel_leaves_no_partial_files(self):
        job, plan = self.scan()
        cancel = threading.Event()
        cancel.set()
        cj = CopyJob(plan, [(b, b["suggested_dest"]) for b in plan["blocks"]], job.run_dir, cancel=cancel)
        counts = cj.run()
        self.assertEqual(counts["copied"], 0)
        self.assertIsNotNone(cj.stopped_reason)

    def test_destination_must_stay_on_target(self):
        with self.assertRaises(ValueError):
            clean_dest("../outside", self.tgt)
        with self.assertRaises(ValueError):
            clean_dest(self.src, self.tgt)
        self.assertEqual(clean_dest(os.path.join(self.tgt, "A", "B"), self.tgt), os.path.join("A", "B"))


if __name__ == "__main__":
    unittest.main()
