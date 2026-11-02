# Argus

A small floating watcher for [Hermes Agent](https://github.com/NousResearch/hermes-agent).
Click the icon and it tells you, in plain English, **what your agent is doing right now**, **which commands it ran
and what they do**, and **which files it saw, read, changed or deleted**. It never interrupts the agent.

> Not affiliated with Nous Research. Argus is an independent community tool.

## What you get

- **A floating icon** (the Hermes caduceus). It turns red when the agent just ran something risky, and dims when idle.
- **A live feed.** Every new action slides in at the bottom as a plain sentence, for example
  *"Searching your home folder for folders named 'argus'"*, with the risk in everyday words
  (*Safe: it only looks, nothing is changed* / *Deletes things, this can't be undone*).
  Click **details** on any message to see the exact command.
- **A files report** for the current session: **Deleted**, **Changed or created**, **Read**, **Seen**.
- **Read-only and private.** See [Safety and privacy](#safety-and-privacy).

## Requirements

- Hermes Agent, installed and used at least once **on the same computer**.
- Python 3.11 or newer with Tk (the Windows installer from python.org includes it). No `pip install` needed.
- Windows is the supported platform. See [Limits](#limits) for Linux and macOS.

## Install and run

```
git clone https://github.com/<your-username>/argus.git
cd argus
py argus_widget.py
```

Double-click `run_argus.bat` to start it without a console window.
Click the icon to open the panel, drag the title to move it, press `Esc` or `-` to collapse, `x` to quit.

## How it connects to your agent

It doesn't. There is no plugin, API key, or server to set up, and nothing is installed into Hermes.
Hermes already records every tool call it makes in a local SQLite database (`state.db`).
Argus opens that file **read-only** and turns the rows into plain English.

It finds your data automatically, in this order:

1. the `HERMES_HOME` environment variable
2. `%LOCALAPPDATA%\hermes` (Windows)
3. `~/.hermes`

Inside that folder it reads `active_profile` to pick your profile, then `profiles/<name>/state.db`
and `profiles/<name>/runtime/active_sessions.json` to find the session that is running now.

Different location or profile:

```
py argus_widget.py --base "D:\hermes" --profile work
```

Check that Argus understands your Hermes data (run this first if something looks wrong):

```
py argus_core.py doctor
```

## Let your agent install it

Paste this to your Hermes Agent (replace the URL if you use a fork):

```
Install Argus, a read-only monitor for you, on this computer.
1. Clone https://github.com/<your-username>/argus.git into a NEW folder called argus in my home folder.
2. Inside it run `py test_argus.py` and `py test_widget.py` and tell me the results.
3. Run `py argus_core.py doctor` and show me the output.
4. Start it in the background (on Windows: `Start-Process pyw argus_widget.py`).
Do not modify any Hermes files or config, and do not open .env or auth.json.
```

## Command line (no window)

```
py argus_core.py status          what is the agent doing right now
py argus_core.py commands -n 10  recent commands, explained, with a risk tag
py argus_core.py files           what it can access and what changed (uses local git)
py argus_core.py watch           live feed in the terminal
```

Add `--json` to `status`, `commands` or `files` for machine-readable output.

## Safety and privacy

- **Read-only.** The database is opened with SQLite `mode=ro` plus `PRAGMA query_only`.
  Argus cannot write to Hermes' data, and reading does not block the agent.
- **It never opens `.env` or `auth.json`.** (The command-line `files` command reads a few terminal-related lines from `config.yaml`, redacted.)
- **Secrets are redacted** before anything is shown: API keys, tokens, bearer headers, passwords,
  URLs with embedded credentials, and `ngrok` hostnames.
- **No network access and no telemetry.** The only subprocess it starts is a local `git status`/`git diff`,
  and only for the command-line `files` command.
- It shows what Hermes' tool calls say. A saved-logins tool call (`browser_vault_*`) is flagged as dangerous
  so you notice when the agent touches your credentials.

## Limits

- **Built against Hermes Agent v0.21.3 on Windows**, which is the database format it understands. Hermes can change that format in later versions.
  If Argus stops understanding it, run `py argus_core.py doctor` and open an issue with the output (values are hidden).
- **Linux and macOS:** the command-line tools should work (plain Python and SQLite). The window is untested there,
  and the icon-shaped transparent window and rounded corners use a Windows-only Tk feature,
  so expect a dark rectangle behind them.
- **Remote Hermes (VPS, Docker, WSL):** Argus must run where `state.db` lives, or be pointed at a copy with `--base`.
  A copy needs `state.db` and `state.db-wal` together, and it won't update live.
- **File tracking only covers what Hermes' tool calls reveal.** Files opened inside a script or code the agent runs
  can't be seen. The panel says so.
- **The command translator knows common commands** (files, Python, npm, git, internet, databases, Windows tools).
  Unknown programs show as *"Running a program called 'x'"*. Pull requests that teach it more are welcome.
- Only the active session is shown.

## Tests

```
py test_argus.py
py test_widget.py
```

Neither needs Hermes installed, and neither opens a window.

## Credits and license

MIT, see `LICENSE`.
The floating icon is adapted from the artwork in the Hermes Agent terminal banner.
"Hermes" and "Nous Research" belong to their owners. If you would rather use your own icon,
replace the images in `argus_assets.py`.
