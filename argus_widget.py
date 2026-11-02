#!/usr/bin/env python3
"""
Argus widget - floating Hermes-style observer.

  py argus_widget.py           (double-click run_argus.bat to start without a console window)

* Collapsed: just the floating Hermes caduceus (red when a risky command just ran, dim when idle).
* Click the icon to open the panel. Drag the title to move it. Esc or "-" collapses, "x" quits.
* The panel is a live feed: every new thing Hermes does slides in at the bottom.
  Filters: All / Commands / Files.
* READ-ONLY: it only reads Hermes' state.db. It never talks to or interrupts the agent.
"""
import argparse
import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont

from argus_assets import ICON_SIZE, ICONS, KEY, PANEL, PANEL_SIZE
from argus_core import AREA_TITLE, FileLedger, Hermes, fn_feed, fn_status, redact

# ---- Hermes palette (sampled from the Hermes terminal UI)
BG = "#000000"
GOLD = "#FFD700"      # headings
AMBER = "#FFBF00"     # body / rules
BRONZE = "#CD7F32"    # box border
DIM = "#B8860B"       # dim text
TAN = "#DCBF74"       # soft text
WHITE = "#FFFFFF"
TIME = "#8C6A14"
RED = "#FF4136"
RISK_COLOR = {"safe": "#8FBF3A", "runs-code": AMBER, "modifies": "#FFA726", "network": TAN,
              "install": BRONZE, "delete": "#FF6B35", "danger": RED}
RISK_LABEL = {"safe": "SAFE", "runs-code": "RUNS CODE", "modifies": "CHANGES FILES", "network": "NETWORK",
              "install": "INSTALLS", "delete": "DELETES", "danger": "DANGER"}
ALERT_RISKS = ("danger", "delete")
ALERT_WINDOW = 180      # seconds a risky command keeps the icon red
IDLE_AFTER = 90         # seconds without activity before the icon dims
MAX_EVENTS = 150
GAP = 26                # px a new message rises from
BASE_GAP = 12           # px between messages
FONT_CANDIDATES = ("Cascadia Mono", "Cascadia Code", "JetBrains Mono", "Consolas", "Lucida Console",
                   "DejaVu Sans Mono", "Courier New")

PW, PH = PANEL_SIZE
IW, IH = ICON_SIZE


# ---------------------------------------------------------------- pure logic (testable without a display)
def event_lines(ev):
    """One feed message -> lines; a line is a list of (text, role).
    Shown: title (+ small 'details' toggle) and time, a plain sentence, the risk in words.
    Hidden until clicked: the exact command / full path."""
    raw = ev.get("raw") or ""
    l1 = [("▸ ", "bullet"), (ev["title"], "title")]
    if raw:
        l1 += [("  ▸ details", "hint_show"), ("  ▾ details", "hint_hide")]
    l1.append(("\t" + ev["time"], "time"))
    lines = [l1]
    plain = ev.get("plain") or ev.get("explain") or ""
    if plain:
        lines.append([(plain, "plain")])
    if ev.get("risk_text"):
        lines.append([(ev["risk_text"], "risk")])
    if raw:
        lines.append([(ev.get("raw_label", "Details: "), "raw_lbl"), (raw, "raw")])
    return lines


def event_colors(ev):
    risk = ev.get("risk", "safe")
    hot = risk in ALERT_RISKS
    return {"bullet": RISK_COLOR.get(risk, AMBER), "title": RISK_COLOR[risk] if hot else GOLD, "time": TIME,
            "plain": WHITE, "risk": RISK_COLOR.get(risk, AMBER), "hint_show": DIM, "hint_hide": DIM,
            "raw_lbl": DIM, "raw": TAN}


FILE_SECTIONS = (("deleted", "Deleted"), ("changed", "Changed or created"), ("read", "Read (opened)"),
                 ("seen", "Seen (looked at or searched)"))


def files_lines(rep):
    """Files report -> [(paragraph_style, [(text, role), ...])]. Pure, so it can be tested without a display."""
    if not rep:
        return [("ROW", [("Loading…", "none")])]
    t = rep["totals"]
    out = [("SUM", [(f"{t['deleted']} deleted · {t['changed']} changed · {t['read']} read · {t['seen']} seen", "sum")]),
           ("SUM", [("Files Hermes touched in this session", "note")])]
    for sec, title in FILE_SECTIONS:
        out.append(("HEAD", [(title, "h_" + sec), (f"  {t[sec]}", "note")]))
        if not rep[sec]:
            out.append(("ROW", [("Nothing was deleted" if sec == "deleted" else "None", "none_ok" if sec == "deleted" else "none")]))
        for r in rep[sec]:
            out.append(("ROW", [("~ (your home folder)" if r["path"] == "~" else r["path"], "path")]))
            meta = [r["when"]] + ([r["note"]] if r["note"] else []) + ([f"×{r['count']}"] if r["count"] > 1 else [])
            out.append(("META", [(" · ".join(m for m in meta if m), "note")]))
        if rep.get(sec + "_more"):
            out.append(("ROW", [(f"+ {rep[sec + '_more']} more", "note")]))
    out.append(("FOOT", [("Files used inside scripts or code can't be tracked.", "note")]))
    return out


def matches(ev, flt):
    return flt == "all" or (flt == "commands" and ev["kind"] == "command")   # "files" shows the file report, not the feed


def mix(c1, c2, t):
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def icon_variant(status, events, now=None):
    """'alert' | 'idle' | 'normal' for the floating icon."""
    now = now or time.time()
    if status and status.get("error"):
        return "alert"
    for ev in reversed(events or []):
        try:
            recent = now - float(ev.get("ts") or 0) < ALERT_WINDOW
        except Exception:
            recent = False
        if recent and ev.get("risk") in ALERT_RISKS:
            return "alert"
    if status:
        idle = status.get("idle_seconds")
        if idle is not None and idle > IDLE_AFTER:
            return "idle"
    return "normal"


def now_text(status, variant):
    if status and status.get("error"):
        return "cannot read Hermes data"
    if not status:
        return "starting"
    area = status.get("area") or "waiting"
    title = AREA_TITLE.get(area, area[:1].upper() + area[1:])
    return f"Idle (last: {title.lower()})" if variant == "idle" else title


# ---------------------------------------------------------------- the widget
class Widget:
    ANIM_MS = 420
    INTERVAL = 1.2

    def __init__(self, base=None, profile=None):
        self.base, self.profile = base, profile
        self.q = queue.Queue()
        self.expanded, self.running = False, True
        self.flt = "all"
        self.events, self.shown = [], 0
        self.status, self.error, self.fresh = None, None, True
        self.files_report = None
        self.variant, self.pulse_until = "normal", 0.0
        self.cursor_on = True
        self.tagnames = []

        r = self.root = tk.Tk()
        r.title("Argus")
        r.overrideredirect(True)
        r.attributes("-topmost", True)
        r.configure(bg=KEY)
        try:  # Windows: this colour becomes truly transparent -> real rounded corners + icon-shaped window
            r.attributes("-transparentcolor", KEY)
        except tk.TclError:
            pass
        sw = r.winfo_screenwidth()
        r.geometry(f"{IW}x{IH}+{max(sw - IW - 28, 0)}+28")

        fams = set(tkfont.families(r))
        self.fam = next((f for f in FONT_CANDIDATES if f in fams), "Courier")
        self.f_norm = tkfont.Font(family=self.fam, size=10)
        self.f_bold = tkfont.Font(family=self.fam, size=10, weight="bold")
        self.f_title = tkfont.Font(family=self.fam, size=13, weight="bold")
        self.f_chip = tkfont.Font(family=self.fam, size=10)
        self.f_chip_on = tkfont.Font(family=self.fam, size=10, weight="bold", underline=True)

        self.cv = tk.Canvas(r, bg=KEY, highlightthickness=0, bd=0, width=IW, height=IH, cursor="hand2")
        self.cv.pack(fill="both", expand=True)
        self.imgs = {k: tk.PhotoImage(data=v) for k, v in ICONS.items()}
        self.panel_img = tk.PhotoImage(data=PANEL)
        self.icon_item = self.cv.create_image(0, 0, anchor="nw", image=self.imgs["normal"])
        self._build_panel()
        self.cv.tag_bind(self.icon_item, "<ButtonPress-1>", self._press)
        self.cv.tag_bind(self.icon_item, "<B1-Motion>", self._motion)
        self.cv.tag_bind(self.icon_item, "<ButtonRelease-1>", self._release)

        r.bind("<Escape>", lambda e: self.collapse())
        threading.Thread(target=self._worker, daemon=True).start()
        r.after(250, self._poll)
        r.after(500, self._blink)

    # ---- panel construction (all drawn on the canvas, so nothing square peeks out of the rounded corners)
    def _build_panel(self):
        cv, cx = self.cv, PW // 2
        cv.create_image(0, 0, anchor="nw", image=self.panel_img, tags=("ui", "drag"), state="hidden")
        cv.create_line(30, 54, cx - 48, 54, fill=AMBER, tags=("ui", "drag"), state="hidden")
        cv.create_line(cx + 48, 54, PW - 30, 54, fill=AMBER, tags=("ui", "drag"), state="hidden")
        cv.create_text(cx, 54, text="Argus", fill=GOLD, font=self.f_title, tags=("ui", "drag"), state="hidden")
        self.now_item = cv.create_text(cx, 80, text="", fill=TAN, font=self.f_norm, tags=("ui", "drag"), state="hidden")
        cv.create_line(30, 102, PW - 30, 102, fill=DIM, tags=("ui", "drag"), state="hidden")
        for name, sym, x in (("min", "–", PW - 66), ("close", "✕", PW - 38)):
            it = cv.create_text(x, 26, text=sym, fill=DIM, font=self.f_bold, tags=("ui", "ctl_" + name), state="hidden")
            cv.tag_bind(it, "<Enter>", lambda e, i=it: cv.itemconfigure(i, fill=GOLD))
            cv.tag_bind(it, "<Leave>", lambda e, i=it: cv.itemconfigure(i, fill=DIM))
        cv.tag_bind("ctl_min", "<Button-1>", lambda e: self.collapse())
        cv.tag_bind("ctl_close", "<Button-1>", lambda e: self.quit())
        self.chips, x = {}, 32
        for key, label in (("all", "All"), ("commands", "Commands"), ("files", "Files")):
            it = cv.create_text(x, 124, text=label, anchor="w", fill=DIM, font=self.f_chip, tags=("ui", "chip"), state="hidden")
            cv.tag_bind(it, "<Button-1>", lambda e, k=key: self.set_filter(k))
            self.chips[key] = it
            x += self.f_chip_on.measure(label) + 26
        cv.tag_bind("drag", "<ButtonPress-1>", self._press)
        cv.tag_bind("drag", "<B1-Motion>", self._motion)
        cv.tag_bind("drag", "<ButtonRelease-1>", self._release)

        fw, fh = PW - 48, PH - 150 - 26
        self.feed = tk.Text(cv, bg=BG, fg=TAN, bd=0, highlightthickness=0, wrap="word", font=self.f_norm, padx=6, pady=4,
                            cursor="arrow", state="disabled", insertwidth=0, selectbackground="#3a2a00",
                            inactiveselectbackground="#3a2a00", spacing1=0, spacing2=1, spacing3=0)
        cv.create_window(24, 142, anchor="nw", window=self.feed, width=fw, height=fh, tags="ui", state="hidden")
        tabpx = str(fw - 12 - 6)
        self.feed.tag_configure("L1", lmargin1=0, lmargin2=18, tabs=(tabpx, "right"))
        self.feed.tag_configure("L2", lmargin1=18, lmargin2=18)
        self.feed.tag_configure("empty", foreground=DIM)
        self.feed.tag_configure("HEAD", spacing1=14, lmargin1=0, lmargin2=0)
        self.feed.tag_configure("ROW", spacing1=5, lmargin1=14, lmargin2=28)
        self.feed.tag_configure("SUM", spacing1=0, lmargin1=0, lmargin2=0)
        self.feed.tag_configure("META", spacing1=0, lmargin1=28, lmargin2=28)
        self.feed.tag_configure("FOOT", spacing1=16, lmargin1=0, lmargin2=0)
        for role, color, bold in (("sum", WHITE, True), ("note", DIM, False), ("path", WHITE, False), ("time", TIME, False),
                                  ("none", DIM, False), ("none_ok", "#8FBF3A", False), ("h_deleted", RISK_COLOR["delete"], True),
                                  ("h_changed", RISK_COLOR["modifies"], True), ("h_read", GOLD, True), ("h_seen", "#8FBF3A", True)):
            self.feed.tag_configure("f_" + role, foreground=color, font=self.f_bold if bold else self.f_norm)
        self._style_chips()

    def _style_chips(self):
        for k, it in self.chips.items():
            on = k == self.flt
            self.cv.itemconfigure(it, fill=GOLD if on else DIM, font=self.f_chip_on if on else self.f_chip)

    # ---- drag / click
    def _press(self, e):
        self._dx, self._dy = e.x_root - self.root.winfo_x(), e.y_root - self.root.winfo_y()
        self._p0, self._moved = (e.x_root, e.y_root), False

    def _motion(self, e):
        if abs(e.x_root - self._p0[0]) > 3 or abs(e.y_root - self._p0[1]) > 3:
            self._moved = True
        if self._moved:
            self.root.geometry(f"+{e.x_root - self._dx}+{e.y_root - self._dy}")

    def _release(self, e):
        if not self._moved and not self.expanded:
            self.expand()

    # ---- expand / collapse
    def expand(self):
        self.expanded = True
        self.cv.itemconfigure(self.icon_item, state="hidden")
        self.cv.itemconfigure("ui", state="normal")
        self.cv.config(width=PW, height=PH, cursor="arrow")
        x = min(self.root.winfo_x(), max(self.root.winfo_screenwidth() - PW - 8, 0))
        y = min(self.root.winfo_y(), max(self.root.winfo_screenheight() - PH - 48, 0))
        self.root.geometry(f"{PW}x{PH}+{x}+{y}")
        self.root.focus_force()
        self._rebuild_feed()
        self._update_now()

    def collapse(self):
        if not self.expanded:
            return
        self.expanded = False
        self.cv.itemconfigure("ui", state="hidden")
        self.cv.itemconfigure(self.icon_item, state="normal")
        self.cv.config(width=IW, height=IH, cursor="hand2")
        self.root.geometry(f"{IW}x{IH}+{self.root.winfo_x()}+{self.root.winfo_y()}")

    def quit(self):
        self.running = False
        self.root.destroy()

    def set_filter(self, key):
        self.flt = key
        self._style_chips()
        self._rebuild_feed()

    # ---- background reader (own thread, own read-only DB connection)
    def _worker(self):
        h, sid, last_id, seen, ledger, sent = None, None, 0, set(), FileLedger(), -1
        while self.running:
            payload = {}
            try:
                if h is None:
                    h = Hermes(self.base, self.profile)
                st = fn_status(h)
                cur, _ = h.active_session_id()
                if cur != sid:
                    sid, last_id, seen, ledger, sent = cur, 0, set(), FileLedger(), -1
                    payload["reset"] = True
                evs = []
                if sid:
                    evs, last_id = fn_feed(h, sid, last_id, 14, seen, ledger, h.session(sid).get("cwd"))
                payload.update(status=st, events=evs)
                if ledger.version != sent:
                    payload["files"] = ledger.report()
                    sent = ledger.version
            except (Exception, SystemExit) as ex:
                payload, h = {"error": str(ex) or repr(ex)}, None
            self.q.put(payload)
            end = time.time() + self.INTERVAL
            while self.running and time.time() < end:
                time.sleep(0.05)

    def _poll(self):
        new, changed, files_changed = [], False, False
        try:
            while True:
                p = self.q.get_nowait()
                changed = True
                if "error" in p:
                    self.error = p["error"]
                    continue
                self.error = None
                if p.get("reset"):
                    self.events, self.fresh = [], True
                    self._rebuild_feed()
                self.status = p.get("status")
                new += p.get("events", [])
                if "files" in p:
                    self.files_report, files_changed = p["files"], True
        except queue.Empty:
            pass
        if changed:
            animate = not self.fresh
            if new:
                self.fresh = False
                self._add_events(new, animate)
            elif self.status:
                self.fresh = False
            if files_changed and self.expanded and self.flt == "files":
                self._render_files()
            self._refresh_icon()
            self._update_now()
        if self.running:
            self.root.after(250, self._poll)

    # ---- icon + header status
    def _refresh_icon(self):
        st = {"error": self.error} if self.error else self.status
        self.variant = icon_variant(st, self.events)
        if not self.expanded:
            show = "pulse" if time.time() < self.pulse_until and self.variant == "normal" else self.variant
            self.cv.itemconfigure(self.icon_item, image=self.imgs[show])

    def _update_now(self):
        if not self.expanded:
            return
        st = {"error": self.error} if self.error else self.status
        txt = now_text(st, self.variant)
        if self.events and not self.error:  # most specific: the title of what it did last
            last = self.events[-1]["title"]
            txt = f"Idle (last: {last.lower()})" if self.variant == "idle" else last
        color = RED if self.variant == "alert" else (DIM if self.variant == "idle" else TAN)
        self.cv.itemconfigure(self.now_item, text=txt + ("▌" if self.cursor_on else " "), fill=color)

    def _blink(self):
        self.cursor_on = not self.cursor_on
        self._update_now()
        if self.running:
            self.root.after(520, self._blink)

    # ---- feed
    def _add_events(self, evs, animate):
        for ev in evs:
            self.events.append(ev)
        if len(self.events) > MAX_EVENTS:
            self.events = self.events[-MAX_EVENTS:]
            if self.expanded:
                self._rebuild_feed()
                evs = []
        if not self.expanded:
            if animate and evs:
                self.pulse_until = time.time() + 0.7
                self.root.after(750, self._refresh_icon)
            return
        for ev in evs:
            if matches(ev, self.flt):
                self._insert(ev, animate)

    def _rebuild_feed(self):
        if not self.expanded:
            return
        if self.flt == "files":
            self._render_files(scroll_top=True)
            return
        f = self.feed
        f.config(state="normal")
        f.delete("1.0", "end")
        for t in self.tagnames:
            f.tag_delete(t)
        self.tagnames, self.shown = [], 0
        f.config(state="disabled")
        vis = [e for e in self.events if matches(e, self.flt)]
        for ev in vis:
            self._insert(ev, False)
        if not vis:
            f.config(state="normal")
            f.insert("end", "Waiting for Hermes…" if self.flt == "all" else "Nothing here yet.", "empty")
            f.config(state="disabled")
        f.yview_moveto(1.0)

    def _render_files(self, scroll_top=False):
        f = self.feed
        first = 0.0 if scroll_top else f.yview()[0]
        f.config(state="normal")
        f.delete("1.0", "end")
        for t in self.tagnames:
            f.tag_delete(t)
        self.tagnames, self.shown = [], 0
        for i, (para, segs) in enumerate(files_lines(self.files_report)):
            if i:
                f.insert("end-1c", "\n")
            a = f.index("end-1c")
            for text, role in segs:
                f.insert("end-1c", text, "f_" + role)
            f.tag_add(para, a, f.index("end-1c"))
        f.config(state="disabled")
        f.yview_moveto(first)

    def _insert(self, ev, animate):
        f, idx = self.feed, self.shown
        f.config(state="normal")
        if self.shown == 0 and f.get("1.0", "end-1c").strip():
            f.delete("1.0", "end")  # drop the "waiting" placeholder
        at_bottom = f.yview()[1] >= 0.985
        spec = event_colors(ev)
        opened = bool(ev.get("open"))
        for role, color in spec.items():
            name = f"m{idx}_{role}"
            f.tag_configure(name, foreground=BG if animate else color,
                            font=self.f_bold if role in ("bullet", "title", "risk") else self.f_norm)
            self.tagnames.append(name)
        f.tag_configure(f"m{idx}_raw", elide=not opened)
        f.tag_configure(f"m{idx}_raw_lbl", elide=not opened)
        f.tag_configure(f"m{idx}_hint_show", elide=opened)
        f.tag_configure(f"m{idx}_hint_hide", elide=not opened)
        gap, msg = f"g{idx}", f"msg{idx}"
        self.tagnames += [gap, msg]
        f.tag_configure(gap, spacing1=BASE_GAP)
        if self.shown:
            f.insert("end-1c", "\n")
        lines = event_lines(ev)
        for li, line in enumerate(lines):
            if li:
                hidden_line = line[0][1] in ("raw_lbl", "raw")
                f.insert("end-1c", "\n", f"m{idx}_raw" if hidden_line else ())
            a = f.index("end-1c")
            for text, role in line:
                f.insert("end-1c", text, f"m{idx}_{role}")
            b = f.index("end-1c")
            f.tag_add("L1" if li == 0 else "L2", a, b)
            f.tag_add(msg, a, b)
            if li == 0:
                f.tag_add(gap, a, b)
        if ev.get("raw"):
            f.tag_bind(msg, "<Button-1>", lambda e, i=idx, v=ev: self._toggle(i, v))
            f.tag_bind(msg, "<Enter>", lambda e: f.config(cursor="hand2"))
            f.tag_bind(msg, "<Leave>", lambda e: f.config(cursor="arrow"))
        self.shown += 1
        f.config(state="disabled")
        overflow = (f.yview()[1] - f.yview()[0]) < 0.999
        if at_bottom:
            f.yview_moveto(1.0)
        if animate:
            self._anim(idx, spec, 0, max(self.ANIM_MS // 20, 1), at_bottom, overflow)

    def _toggle(self, idx, ev):
        f = self.feed
        at_bottom = f.yview()[1] >= 0.985
        ev["open"] = opened = not ev.get("open")
        f.tag_configure(f"m{idx}_raw", elide=not opened)
        f.tag_configure(f"m{idx}_raw_lbl", elide=not opened)
        f.tag_configure(f"m{idx}_hint_show", elide=opened)
        f.tag_configure(f"m{idx}_hint_hide", elide=not opened)
        if at_bottom:
            f.yview_moveto(1.0)

    def _anim(self, idx, spec, step, steps, at_bottom, overflow):
        if not self.running or not self.expanded:
            return
        f = self.feed
        t = min(step / steps, 1.0)
        e = 1 - (1 - t) ** 3  # ease-out
        for role, color in spec.items():
            f.tag_configure(f"m{idx}_{role}", foreground=mix(BG, color, e))
        gap = int(GAP * (1 - e))
        if at_bottom and overflow:
            f.yview_moveto(1.0)
            if gap:
                f.yview_scroll(-gap, "pixels")      # long feed: the whole feed rises into place
        else:
            f.tag_configure(f"g{idx}", spacing1=BASE_GAP + gap)  # short feed: the new message rises into place
        if step < steps:
            self.root.after(20, self._anim, idx, spec, step + 1, steps, at_bottom, overflow)
        else:
            f.tag_configure(f"g{idx}", spacing1=BASE_GAP)

    def run(self):
        self.root.mainloop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--profile")
    a = ap.parse_args()
    Widget(a.base, a.profile).run()


if __name__ == "__main__":
    main()
