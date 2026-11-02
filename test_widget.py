"""Tests for widget logic that don't need a display. Run: python test_widget.py"""
import sys, time, types

try:
    import tkinter  # noqa
except ModuleNotFoundError:  # logic below does not use tk
    sys.modules["tkinter"] = types.ModuleType("tkinter")
    sys.modules["tkinter.font"] = types.ModuleType("tkinter.font")
    sys.modules["tkinter"].font = sys.modules["tkinter.font"]

from argus_widget import files_lines, event_lines, event_colors, matches, mix, icon_variant, now_text, RISK_COLOR, RED, GOLD

fails = 0
def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name, extra if not cond else "")
    fails += 0 if cond else 1

flat = lambda lines: "\n".join("".join(t for t, _ in l) for l in lines)
now = time.time()
cmd = {"key": "1", "ts": now - 5, "time": "00:00:10", "kind": "command", "title": "Running a script",
       "plain": "Running the Python program test1/hello.py", "risk_text": "Runs a program on your computer",
       "raw": "python test1/hello.py", "raw_label": "Exact command: ", "risk": "runs-code"}
danger = {"key": "2", "ts": now - 5, "time": "00:00:20", "kind": "command", "title": "Deleting files",
          "plain": "Deleting C:\\ and everything inside it", "risk_text": "Dangerous: could harm your computer",
          "raw": "rm -rf C:\\", "raw_label": "Exact command: ", "risk": "danger"}
fil = {"key": "3", "ts": now - 5, "time": "00:00:30", "kind": "file", "title": "Writing a script",
       "plain": "Created or changed hello.py", "risk_text": "Changes something on your computer",
       "raw": "C:\\Users\\alice\\test1\\hello.py", "raw_label": "Full path: ", "risk": "modifies"}

L = event_lines(cmd)
t = flat(L)
check("line 1: bullet, title, time", t.startswith("▸ Running a script") and L[0][-1] == ("\t00:00:10", "time"))
check("line 2: plain sentence", L[1] == [("Running the Python program test1/hello.py", "plain")])
check("line 3: risk in words", L[2][0] == ("Runs a program on your computer", "risk"))
check("line 1: click hint sits next to the title", {r for _, r in L[0]} >= {"hint_show", "hint_hide"})
check("line 4: exact command kept for click-to-reveal", L[3] == [("Exact command: ", "raw_lbl"), ("python test1/hello.py", "raw")])
check("no jargon in visible lines", "dictionary" not in t and "nested shell" not in t)
check("no hint/raw when nothing to reveal", len(event_lines(dict(cmd, raw=""))) == 3 and
      all(r not in ("hint_show", "hint_hide") for l in event_lines(dict(cmd, raw="")) for _, r in l))
check("file event has full path hidden", event_lines(fil)[-1][0] == ("Full path: ", "raw_lbl"))
check("roles are known", all(r in event_colors(cmd) for l in event_lines(cmd) for _, r in l))
check("danger title is red", event_colors(danger)["title"] == RISK_COLOR["danger"])
check("normal title is gold", event_colors(cmd)["title"] == GOLD)

check("filter all", all(matches(e, "all") for e in (cmd, fil)))
check("filter commands", matches(cmd, "commands") and not matches(fil, "commands"))
check("files chip shows the report, not the feed", not matches(fil, "files") and not matches(cmd, "files"))

check("mix 0", mix("#000000", "#ffd700", 0) == "#000000")
check("mix 1", mix("#000000", "#ffd700", 1) == "#ffd700")
check("mix half", mix("#000000", "#ffffff", 0.5) in ("#808080", "#7f7f7f"))

st = {"area": "running a script", "idle_seconds": 4}
check("icon normal", icon_variant(st, [cmd], now) == "normal")
check("icon alert on recent danger", icon_variant(st, [cmd, danger], now) == "alert")
check("icon alert on recent delete", icon_variant(st, [dict(danger, risk="delete")], now) == "alert")
check("old danger does not alert", icon_variant(st, [dict(danger, ts=now - 999)], now) == "normal")
check("icon idle", icon_variant({"area": "x", "idle_seconds": 500}, [], now) == "idle")
check("icon alert on error", icon_variant({"error": "x"}, [], now) == "alert")
check("icon normal when starting", icon_variant(None, None, now) == "normal")
check("now text", now_text(st, "normal") == "Running a script")
check("now text idle", now_text({"area": "reading files"}, "idle") == "Idle (last: reading a file)")
check("now text error", now_text({"error": "boom"}, "alert") == "cannot read Hermes data")
check("now text starting", now_text(None, "normal") == "starting")

rep = {"totals": {"deleted": 1, "changed": 2, "read": 1, "seen": 0},
       "deleted": [{"path": "~\\build", "count": 1, "when": "20:11", "note": ""}], "deleted_more": 0,
       "changed": [{"path": "~\\a.txt", "count": 1, "when": "20:12", "note": "moved to ~\\b.txt"},
                   {"path": "~\\x.py", "count": 3, "when": "20:13", "note": "changed"}], "changed_more": 0,
       "read": [{"path": "~", "count": 1, "when": "20:14", "note": ""}], "read_more": 2, "seen": [], "seen_more": 0}
FL = files_lines(rep)
ft = "\n".join("".join(x for x, _ in segs) for _, segs in FL)
check("files: summary counts", "1 deleted · 2 changed · 1 read · 0 seen" in ft)
check("files: four sections in order", ft.index("Deleted") < ft.index("Changed or created") < ft.index("Read (opened)") < ft.index("Seen"))
check("files: move note + count", "moved to ~\\b.txt" in ft and "×3" in ft)
check("files: home folder spelled out", "~ (your home folder)" in ft)
check("files: empty section says None", "None" in ft)
check("files: overflow note", "+ 2 more" in ft)
check("files: nothing deleted message", "Nothing was deleted" in "\n".join("".join(x for x, _ in s) for _, s in files_lines(dict(rep, deleted=[], totals=dict(rep["totals"], deleted=0)))))
check("files: loading state", files_lines(None)[0][1][0][0].startswith("Loading"))
check("files: footnote about scripts", "inside scripts" in ft)

print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
